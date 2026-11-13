#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use data_encoding::{BASE64, BASE64_NOPAD};
use oxish_client::host_key::fingerprint;
use oxish_client::oxish_proto::named::PublicKeyAlgorithm;
use oxish_client::oxish_proto::{Encode, OpenSshKeyV1, SshPrivateKey, pem_encode};
use oxish_client::{DEFAULT_PROVIDER, cpu};
use zeroize::Zeroizing;

const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const KEY_TYPE: &[u8] = b"ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\0";

const USAGE: &str = "\
usage: oxish-keygen -f PATH [-C COMMENT]     generate an Ed25519 key pair at PATH and PATH.pub
       oxish-keygen -y -f PRIVATE_KEY        print the public key of a private key
       oxish-keygen -l -f FILE               print the SHA256 fingerprint of a private or public key

A new key never replaces an existing file and is never written through a symbolic link.
The private key file is created with mode 0600 and is not encrypted.
";

enum Mode {
    Generate,
    PublicKey,
    Fingerprint,
}

struct Args {
    mode: Mode,
    path: PathBuf,
    comment: String,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut mode = Mode::Generate;
    let mut moded = false;
    let mut path = None;
    let mut comment = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some(flag @ ("-y" | "-l")) => {
                if moded {
                    return Err("-y and -l cannot be combined".to_owned());
                }
                moded = true;
                mode = if flag == "-y" { Mode::PublicKey } else { Mode::Fingerprint };
            }
            Some("-f") => {
                let value = args.next().ok_or("-f needs a path")?;
                if path.replace(PathBuf::from(value)).is_some() {
                    return Err("-f given twice".to_owned());
                }
            }
            Some("-C") => {
                let value = args.next().ok_or("-C needs a comment")?;
                let value = value.into_string().map_err(|_| "the comment is not UTF-8")?;
                if comment.replace(value).is_some() {
                    return Err("-C given twice".to_owned());
                }
            }
            _ => return Err(format!("unexpected argument {arg:?}")),
        }
    }
    let path = path.ok_or("-f is required")?;
    if path.as_os_str().is_empty() {
        return Err("-f needs a path".to_owned());
    }
    if comment.is_some() && !matches!(mode, Mode::Generate) {
        return Err("-C applies only when generating a key".to_owned());
    }
    let comment = comment.unwrap_or_default();
    if comment.chars().any(char::is_control) {
        return Err("the comment must not contain control characters".to_owned());
    }
    Ok(Some(Args { mode, path, comment }))
}

fn put_string(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32, String> {
        let (head, rest) = self.0.split_first_chunk::<4>().ok_or("truncated key")?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Result<&'a [u8], String> {
        let length = self.u32()? as usize;
        if self.0.len() < length {
            return Err("truncated key".to_owned());
        }
        let (head, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(head)
    }
}

fn public_blob(public: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, KEY_TYPE);
    put_string(&mut blob, public);
    blob
}

fn public_line(blob: &[u8], comment: &str) -> String {
    let mut line = format!("ssh-ed25519 {}", BASE64.encode(blob));
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(comment);
    }
    line.push('\n');
    line
}

fn fingerprint_line(blob: &[u8], comment: &str) -> Result<String, String> {
    let print = fingerprint(blob, DEFAULT_PROVIDER).map_err(|error| error.to_string())?;
    let mut line = format!("256 {print}");
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(comment);
    }
    line.push_str(" (ED25519)\n");
    Ok(line)
}

fn private_key_file(comment: &str) -> Result<(Zeroizing<String>, Vec<u8>), String> {
    let provider = DEFAULT_PROVIDER;
    let (signing, pkcs8) = provider
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .map_err(|error| format!("cannot generate a key: {error}"))?;
    let pkcs8 = Zeroizing::new(pkcs8);
    let single = SshPrivateKey::from_pkcs8(&pkcs8, &*signing).map_err(|error| error.to_string())?;
    let public = public_blob(signing.public_key());

    let mut check = [0u8; 4];
    provider
        .secure_random()
        .fill(&mut check)
        .map_err(|error| format!("cannot gather randomness: {error}"))?;
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    single.encode(&mut private);
    put_string(&mut private, comment.as_bytes());
    for pad in 1..=((8 - private.len() % 8) % 8) {
        private.push(pad as u8);
    }

    let mut blob = Zeroizing::new(MAGIC.to_vec());
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &public);
    put_string(&mut blob, &private);
    Ok((pem_encode("OPENSSH PRIVATE KEY", &blob), public))
}

fn create_new(path: &Path, mode: u32) -> Result<File, String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!("{} is a symbolic link; refusing to write through it", path.display()));
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => {
                format!("{} already exists; refusing to overwrite it", path.display())
            }
            _ => format!("cannot create {}: {error}", path.display()),
        })
}

fn generate(path: &Path, comment: &str) -> Result<String, String> {
    let mut pub_name = path.as_os_str().to_owned();
    pub_name.push(".pub");
    let pub_path = PathBuf::from(pub_name);
    let (pem, public) = private_key_file(comment)?;

    let mut private_file = create_new(path, 0o600)?;
    let written = private_file
        .write_all(pem.as_bytes())
        .and_then(|()| private_file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()));
    let written = written.and_then(|()| {
        let mut file = create_new(&pub_path, 0o644)?;
        file.write_all(public_line(&public, comment).as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                let _ = fs::remove_file(&pub_path);
                format!("cannot write {}: {error}", pub_path.display())
            })
    });
    if let Err(error) = written {
        drop(private_file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    eprintln!("oxish-keygen: wrote {} and {}", path.display(), pub_path.display());
    fingerprint_line(&public, comment)
}

fn read_private(path: &Path) -> Result<(Vec<u8>, String), String> {
    let refuse = |detail: String| format!("{}: {detail}", path.display());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|error| refuse(format!("cannot read: {error}")))?;
    let metadata = file.metadata().map_err(|error| refuse(format!("cannot read: {error}")))?;
    if !metadata.is_file() {
        return Err(refuse("not a regular file".to_owned()));
    }
    if metadata.uid() == rustix::process::getuid().as_raw() && metadata.mode() & 0o077 != 0 {
        return Err(refuse(format!(
            "permissions {:04o} are too open; a private key must not be accessible by group or others",
            metadata.mode() & 0o7777
        )));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(refuse(format!("larger than {MAX_KEY_FILE_BYTES} bytes")));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refuse(format!("cannot read: {error}")))?;
    let text = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| refuse("not text".to_owned()))?,
    );

    let parsed = OpenSshKeyV1::from_str(&text).map_err(|error| refuse(error.to_string()))?;
    let provider = DEFAULT_PROVIDER;
    let mut keys = parsed.pkcs8_keys();
    let (Some(pkcs8), None) = (keys.next(), keys.next()) else {
        return Err(refuse("expected exactly one key".to_owned()));
    };
    let key = provider
        .signing_key_from_pkcs8(&pkcs8)
        .map_err(|error| refuse(format!("cannot load the key: {error}")))?;
    if key.algorithm() != PublicKeyAlgorithm::Ed25519 {
        return Err(refuse("only Ed25519 keys are supported".to_owned()));
    }
    let comment = embedded_comment(&text).unwrap_or_default();
    Ok((public_blob(key.public_key()), comment))
}

fn embedded_comment(text: &str) -> Option<String> {
    let body: String = text
        .lines()
        .skip_while(|line| *line != "-----BEGIN OPENSSH PRIVATE KEY-----")
        .skip(1)
        .take_while(|line| *line != "-----END OPENSSH PRIVATE KEY-----")
        .collect();
    let blob = Zeroizing::new(BASE64.decode(body.as_bytes()).ok()?);
    let mut reader = Reader(blob.strip_prefix(MAGIC)?);
    reader.string().ok()?;
    reader.string().ok()?;
    reader.string().ok()?;
    let count = reader.u32().ok()?;
    for _ in 0..count {
        reader.string().ok()?;
    }
    let mut private = Reader(reader.string().ok()?);
    private.u32().ok()?;
    private.u32().ok()?;
    if private.string().ok()? != KEY_TYPE {
        return None;
    }
    private.string().ok()?;
    private.string().ok()?;
    let comment = String::from_utf8(private.string().ok()?.to_vec()).ok()?;
    (!comment.chars().any(char::is_control)).then_some(comment)
}

fn read_public(text: &str) -> Result<(Vec<u8>, String), String> {
    let line = text.lines().next().ok_or("empty file")?;
    let mut fields = line.splitn(3, [' ', '\t']);
    if fields.next() != Some("ssh-ed25519") {
        return Err("not an ssh-ed25519 public key".to_owned());
    }
    let encoded = fields.next().ok_or("missing key data")?;
    let blob = BASE64
        .decode(encoded.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(encoded.as_bytes()))
        .map_err(|_| "key data is not base64")?;
    let mut reader = Reader(&blob);
    let valid = reader.string().is_ok_and(|kind| kind == KEY_TYPE)
        && reader.string().is_ok_and(|key| key.len() == 32)
        && reader.0.is_empty();
    if !valid {
        return Err("malformed ssh-ed25519 public key".to_owned());
    }
    let comment = fields.next().unwrap_or_default().trim().to_owned();
    Ok((blob, comment))
}

fn read_any(path: &Path) -> Result<(Vec<u8>, String), String> {
    let file = File::open(path).map_err(|error| format!("{}: cannot read: {error}", path.display()))?;
    let mut head = Vec::new();
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut head)
        .map_err(|error| format!("{}: cannot read: {error}", path.display()))?;
    if head.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        zeroize::Zeroize::zeroize(&mut head);
        return read_private(path);
    }
    let text = std::str::from_utf8(&head).map_err(|_| format!("{}: not text", path.display()))?;
    read_public(text).map_err(|error| format!("{}: {error}", path.display()))
}

fn run(args: Args) -> Result<(), String> {
    cpu::require().map_err(|error| error.to_string())?;
    let output = match args.mode {
        Mode::Generate => generate(&args.path, &args.comment)?,
        Mode::PublicKey => {
            let (blob, comment) = read_private(&args.path)?;
            public_line(&blob, &comment)
        }
        Mode::Fingerprint => {
            let (blob, comment) = read_any(&args.path)?;
            fingerprint_line(&blob, &comment)?
        }
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("cannot write to standard output: {error}"))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("oxish-keygen: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oxish-keygen: {error}");
            ExitCode::FAILURE
        }
    }
}
