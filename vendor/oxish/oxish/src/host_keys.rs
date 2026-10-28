//! Strict host key loading
//!
//! The upstream loader skips unreadable or malformed key files with a warning, which would let a
//! server quietly come up with a different identity than the operator configured. This loader
//! fails on the first problem instead.

use core::str::FromStr as _;
use std::{
    fs::OpenOptions,
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use anyhow::Context as _;
use proto::{HostKeys, OpenSshKeyV1, crypto::CryptoProvider};
use zeroize::Zeroizing;

/// Largest host key file accepted, in bytes
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Load every configured host key, requiring private, owned, regular files
///
/// Each file must be owned by the server user, readable by nobody else, and not a symlink. Any
/// unreadable or malformed file is an error, so the served identity is always the configured one.
pub fn load_host_keys<P: AsRef<Path>>(
    paths: &[P],
    provider: &dyn CryptoProvider,
) -> anyhow::Result<HostKeys> {
    anyhow::ensure!(!paths.is_empty(), "no host key files configured");

    let euid = rustix::process::geteuid().as_raw();
    let mut keys = Vec::new();
    for path in paths {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("failed to open host key `{}`", path.display()))?;
        let meta = file.metadata()?;
        anyhow::ensure!(meta.is_file(), "host key `{}` is not a regular file", path.display());
        anyhow::ensure!(
            meta.uid() == euid && meta.mode() & 0o077 == 0,
            "host key `{}` must be owned by the server user and not accessible by others (mode 0600)",
            path.display()
        );
        anyhow::ensure!(meta.len() <= MAX_KEY_FILE_BYTES, "host key `{}` is too large", path.display());

        let mut pem = Zeroizing::new(String::new());
        file.read_to_string(&mut pem)
            .with_context(|| format!("failed to read host key `{}`", path.display()))?;
        let openssh = OpenSshKeyV1::from_str(&pem)
            .map_err(|error| anyhow::anyhow!("host key `{}` is invalid: {error}", path.display()))?;
        keys.extend(openssh.pkcs8_keys());
    }

    HostKeys::new(keys.into_iter(), provider).map_err(|error| anyhow::anyhow!("host keys rejected: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
    };

    use proto::{SshPrivateKey, named::PublicKeyAlgorithm, pem_encode};

    use super::*;
    use crate::DEFAULT_PROVIDER;

    fn write_key(dir: &Path, name: &str, mode: u32) -> std::path::PathBuf {
        let (key, pkcs8) = DEFAULT_PROVIDER.generate_signing_key(&PublicKeyAlgorithm::Ed25519).unwrap();
        let pkcs8 = Zeroizing::new(pkcs8);
        let private = SshPrivateKey::from_pkcs8(&pkcs8, &*key).unwrap();
        let pem = pem_encode(
            "OPENSSH PRIVATE KEY",
            &OpenSshKeyV1::new([private]).unwrap().to_bytes(DEFAULT_PROVIDER).unwrap(),
        );
        let path = dir.join(name);
        fs::write(&path, pem).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn private_files_load_and_everything_else_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let good = write_key(dir.path(), "good", 0o600);
        let second = write_key(dir.path(), "second", 0o400);
        assert_eq!(load_host_keys(&[&good, &second], DEFAULT_PROVIDER).unwrap().len(), 2);

        let readable = write_key(dir.path(), "readable", 0o644);
        assert!(load_host_keys(&[&readable], DEFAULT_PROVIDER).is_err());
        let group = write_key(dir.path(), "group", 0o640);
        assert!(load_host_keys(&[&group], DEFAULT_PROVIDER).is_err());

        let link = dir.path().join("link");
        symlink(&good, &link).unwrap();
        assert!(load_host_keys(&[&link], DEFAULT_PROVIDER).is_err());

        let junk = dir.path().join("junk");
        fs::write(&junk, "not a key").unwrap();
        fs::set_permissions(&junk, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_host_keys(&[&junk], DEFAULT_PROVIDER).is_err());

        assert!(load_host_keys(&[&good, &dir.path().join("missing")], DEFAULT_PROVIDER).is_err());
        assert!(load_host_keys::<&Path>(&[], DEFAULT_PROVIDER).is_err());
    }
}
