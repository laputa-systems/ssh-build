use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oxish_client::oxish_proto::HostKeys;
use oxish_client::{DEFAULT_PROVIDER, auth::load_key, host_key::fingerprint};
use tempfile::TempDir;

fn keygen(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oxish-keygen")).args(args).output().expect("oxish-keygen runs")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 output")
}

fn openssh(tool: &str) -> PathBuf {
    match std::env::var_os("SSH_BIN_DIR") {
        Some(dir) => PathBuf::from(dir).join(tool),
        None => PathBuf::from(tool),
    }
}

fn generate(dir: &TempDir, name: &str, comment: &str) -> PathBuf {
    let path = dir.path().join(name);
    let output = keygen(&["-f", path_str(&path), "-C", comment]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    path
}

fn pub_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

#[test]
fn a_generated_key_is_private_and_readable_by_our_readers() {
    let dir = TempDir::new().unwrap();
    let path = generate(&dir, "id", "laputa@host");
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
    let public = fs::read_to_string(pub_path(&path)).unwrap();
    assert!(public.starts_with("ssh-ed25519 ") && public.ends_with(" laputa@host\n"), "{public:?}");

    let key = load_key(&path, DEFAULT_PROVIDER).expect("the client reads the key");
    let blob: Vec<u8> = {
        let mut blob = Vec::new();
        for part in [&b"ssh-ed25519"[..], key.public_key()] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        blob
    };
    let theirs = format!("256 {} laputa@host (ED25519)\n", fingerprint(&blob, DEFAULT_PROVIDER).unwrap());
    assert_eq!(stdout(&keygen(&["-l", "-f", path_str(&path)])), theirs);
    assert_eq!(stdout(&keygen(&["-l", "-f", path_str(&pub_path(&path))])), theirs);
    assert_eq!(stdout(&keygen(&["-y", "-f", path_str(&path)])), public);

    let host_keys = HostKeys::from_files([&path].into_iter(), DEFAULT_PROVIDER).expect("the server reads the key");
    assert_eq!(host_keys.len(), 1);
}

#[test]
fn the_generation_summary_is_the_fingerprint() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("id");
    let output = keygen(&["-f", path_str(&path)]);
    assert!(output.status.success());
    assert_eq!(stdout(&output), stdout(&keygen(&["-l", "-f", path_str(&path)])));
    assert!(stdout(&output).starts_with("256 SHA256:") && stdout(&output).ends_with(" (ED25519)\n"));
}

#[test]
fn two_keys_differ() {
    let dir = TempDir::new().unwrap();
    let first = generate(&dir, "a", "");
    let second = generate(&dir, "b", "");
    assert_ne!(
        stdout(&keygen(&["-l", "-f", path_str(&first)])),
        stdout(&keygen(&["-l", "-f", path_str(&second)]))
    );
}

#[test]
fn an_existing_key_is_never_overwritten() {
    let dir = TempDir::new().unwrap();
    let path = generate(&dir, "id", "");
    let before = (fs::read(&path).unwrap(), fs::read(pub_path(&path)).unwrap());
    let output = keygen(&["-f", path_str(&path)]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(before, (fs::read(&path).unwrap(), fs::read(pub_path(&path)).unwrap()));
}

#[test]
fn an_existing_public_file_stops_generation_without_leaving_a_private_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("id");
    fs::write(pub_path(&path), "keep me\n").unwrap();
    assert!(!keygen(&["-f", path_str(&path)]).status.success());
    assert!(!path.exists());
    assert_eq!(fs::read_to_string(pub_path(&path)).unwrap(), "keep me\n");
}

#[test]
fn symbolic_links_are_refused() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("target");
    let dangling = dir.path().join("dangling");
    symlink(&target, &dangling).unwrap();
    assert!(!keygen(&["-f", path_str(&dangling)]).status.success());
    assert!(!target.exists());

    let existing = dir.path().join("existing");
    fs::write(&existing, "data").unwrap();
    let alias = dir.path().join("alias");
    symlink(&existing, &alias).unwrap();
    assert!(!keygen(&["-f", path_str(&alias)]).status.success());
    assert_eq!(fs::read_to_string(&existing).unwrap(), "data");

    let path = dir.path().join("id");
    symlink(&target, pub_path(&path)).unwrap();
    assert!(!keygen(&["-f", path_str(&path)]).status.success());
    assert!(!path.exists() && !target.exists());
}

#[test]
fn a_loose_private_key_is_not_read() {
    let dir = TempDir::new().unwrap();
    let path = generate(&dir, "id", "");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    for mode in ["-y", "-l"] {
        let output = keygen(&[mode, "-f", path_str(&path)]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("too open"));
    }
}

#[test]
fn bad_input_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("junk");
    fs::write(&path, "ssh-rsa AAAA nope\n").unwrap();
    assert!(!keygen(&["-l", "-f", path_str(&path)]).status.success());
    assert!(!keygen(&["-y", "-f", path_str(&path)]).status.success());
    assert!(!keygen(&["-y", "-f", path_str(&dir.path().join("absent"))]).status.success());
    assert!(!keygen(&[]).status.success());
    assert!(!keygen(&["-y", "-l", "-f", path_str(&path)]).status.success());
    assert!(!keygen(&["-f", path_str(&dir.path().join("x")), "-C", "two\nlines"]).status.success());
    assert!(!dir.path().join("x").exists());
}

#[test]
fn openssh_accepts_our_keys_and_agrees_with_us() {
    let ssh_keygen = openssh("ssh-keygen");
    if Command::new(&ssh_keygen).arg("-?").output().is_err() {
        panic!("{} is required for the interop test", ssh_keygen.display());
    }
    let dir = TempDir::new().unwrap();
    for comment in ["", "laputa@host", "with spaces in it"] {
        let path = generate(&dir, &format!("id{}", comment.len()), comment);
        let theirs = Command::new(&ssh_keygen).args(["-l", "-f", path_str(&path)]).output().unwrap();
        assert!(theirs.status.success(), "{}", String::from_utf8_lossy(&theirs.stderr));
        let ours = stdout(&keygen(&["-l", "-f", path_str(&path)]));
        let theirs = stdout(&theirs);
        if comment.is_empty() {
            assert_eq!(ours.split(' ').nth(1), theirs.split(' ').nth(1));
        } else {
            assert_eq!(ours, theirs);
        }

        let theirs = Command::new(&ssh_keygen).args(["-y", "-f", path_str(&path)]).output().unwrap();
        assert!(theirs.status.success());
        assert_eq!(stdout(&theirs), fs::read_to_string(pub_path(&path)).unwrap());
        assert_eq!(stdout(&theirs), stdout(&keygen(&["-y", "-f", path_str(&path)])));

        let public = Command::new(&ssh_keygen).args(["-l", "-f", path_str(&pub_path(&path))]).output().unwrap();
        assert!(public.status.success());
    }
}
