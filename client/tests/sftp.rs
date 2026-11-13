use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use oxish_client::sftp::{Attrs, OpenFlags, Sftp, SftpError, STATUS_NO_SUCH_FILE};
use oxish_client::{ClientConfig, Connection, ExecOptions, ExecStatus};
use sha2::{Digest, Sha256};

const RUN_LIMIT: Duration = Duration::from_secs(180);

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run this test through client/fixture/ssh-fixture.sh exec")
    })
}

struct Fixture {
    host: String,
    port: String,
    pin: String,
    other_pin: String,
    user: String,
    key: String,
}

fn fixture() -> Fixture {
    Fixture {
        host: variable("XINFRA_FIXTURE_A_HOST"),
        port: variable("XINFRA_FIXTURE_A_PORT"),
        pin: variable("XINFRA_FIXTURE_A_HOST_KEY"),
        other_pin: variable("XINFRA_FIXTURE_B_HOST_KEY"),
        user: variable("XINFRA_FIXTURE_USER"),
        key: variable("XINFRA_FIXTURE_KEY"),
    }
}

impl Fixture {
    fn flags(&self) -> Vec<String> {
        vec![
            "-P".to_owned(),
            self.port.clone(),
            "-i".to_owned(),
            self.key.clone(),
            "--host-key".to_owned(),
            self.pin.clone(),
        ]
    }

    fn remote(&self, path: &str) -> String {
        format!("{}@{}:{path}", self.user, self.host)
    }

    fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn connection_to(&self, port: &str) -> Connection {
        let config = ClientConfig::pinned(
            self.host.clone(),
            port.parse().expect("port"),
            &self.user,
            &self.key,
            &self.pin,
            Duration::from_secs(20),
        )
        .expect("pin");
        let mut connection = Connection::connect(&config).expect("connects");
        connection.authenticate().expect("authenticates");
        connection
    }

    fn connection(&self) -> Connection {
        self.connection_to(&self.port)
    }

    fn sftp(&self) -> Sftp {
        Sftp::connect(self.connection(), None).expect("sftp starts")
    }

    fn shell(&self, command: &str) -> String {
        let result = self
            .connection()
            .exec(command, &ExecOptions::default())
            .expect("exec");
        assert_eq!(result.status, ExecStatus::Exited(0), "{command}: {}", String::from_utf8_lossy(&result.stderr));
        String::from_utf8(result.stdout).expect("utf-8")
    }
}

fn run(mut command: Command) -> Output {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let pid = child.id();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(RUN_LIMIT) {
        Ok(output) => output.expect("output"),
        Err(_) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            panic!("{command:?} did not finish in {RUN_LIMIT:?}");
        }
    }
}

fn scp(fixture: &Fixture, extra: &[&str], paths: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-scp"));
    command.args(fixture.flags()).args(extra).args(paths);
    run(command)
}

fn sftp_batch(fixture: &Fixture, directory: &Path, script: &str) -> Output {
    let path = directory.join(format!("batch-{}", COUNTER.fetch_add(1, Ordering::Relaxed)));
    fs::write(&path, script).expect("batch file");
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-sftp"));
    command
        .current_dir(directory)
        .args(fixture.flags())
        .arg("-b")
        .arg(&path)
        .arg(fixture.target());
    run(command)
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Remote {
    fixture: Fixture,
    name: String,
}

impl Remote {
    fn new(label: &str) -> Self {
        let fixture = fixture();
        let name = format!(
            "sftp-test-{}-{}-{label}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        fixture.shell(&format!("mkdir {name}"));
        Self { fixture, name }
    }

    fn path(&self, tail: &str) -> String {
        format!("{}/{tail}", self.name)
    }

    fn spec(&self, tail: &str) -> String {
        self.fixture.remote(&self.path(tail))
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        let _ = self
            .fixture
            .connection()
            .exec(&format!("rm -rf {}", self.name), &ExecOptions::default());
    }
}

fn text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn pseudo_random(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn remote_sum(fixture: &Fixture, path: &str) -> String {
    fixture
        .shell(&format!("sha256sum {path}"))
        .split_whitespace()
        .next()
        .expect("checksum")
        .to_owned()
}

fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, directory: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(directory).expect("read_dir").map(|entry| entry.expect("entry")).collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("prefix").display().to_string();
            if entry.file_type().expect("type").is_dir() {
                out.push(format!("{relative}/"));
                walk(root, &path, out);
            } else {
                let content = fs::read(&path).expect("read");
                out.push(format!("{relative} {}", hex(&content)));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn ten_mib_round_trips_with_equal_checksums() {
    let remote = Remote::new("ten");
    let local = tempfile::tempdir().expect("tempdir");
    let content = pseudo_random(10 * 1024 * 1024 + 123, 7);
    let source = local.path().join("big.bin");
    fs::write(&source, &content).expect("write");

    let up = scp(&remote.fixture, &[], &[source.to_str().expect("utf-8"), &remote.spec("big.bin")]);
    assert!(up.status.success(), "{}", text(&up));
    assert!(up.stdout.is_empty(), "no progress without a terminal: {}", text(&up));
    assert_eq!(remote_sum(&remote.fixture, &remote.path("big.bin")), hex(&content));

    let back = local.path().join("back.bin");
    let down = scp(&remote.fixture, &[], &[&remote.spec("big.bin"), back.to_str().expect("utf-8")]);
    assert!(down.status.success(), "{}", text(&down));
    let downloaded = fs::read(&back).expect("read back");
    assert_eq!(downloaded.len(), content.len());
    assert_eq!(hex(&downloaded), hex(&content));
}

#[test]
fn recursive_copy_keeps_the_directory_structure() {
    let remote = Remote::new("tree");
    let local = tempfile::tempdir().expect("tempdir");
    let top = local.path().join("top");
    fs::create_dir_all(top.join("sub/deeper")).expect("dirs");
    fs::create_dir_all(top.join("empty")).expect("empty");
    fs::write(top.join("a.txt"), b"alpha").expect("a");
    fs::write(top.join("with space.txt"), b"spaced").expect("space");
    fs::write(top.join(".hidden"), b"dot").expect("hidden");
    fs::write(top.join("sub/b.bin"), pseudo_random(300_000, 3)).expect("b");
    fs::write(top.join("sub/deeper/c"), b"").expect("c");
    std::os::unix::fs::symlink("a.txt", top.join("link")).expect("symlink");
    let expected = {
        let mut expected = tree(&top);
        expected.retain(|line| !line.starts_with("link"));
        expected
    };

    let refused = scp(&remote.fixture, &[], &[top.to_str().expect("utf-8"), &remote.spec("")]);
    assert!(!refused.status.success(), "a directory needs -r: {}", text(&refused));

    let up = scp(&remote.fixture, &["-r"], &[top.to_str().expect("utf-8"), &remote.spec("")]);
    assert!(up.status.success(), "{}", text(&up));
    assert!(String::from_utf8_lossy(&up.stderr).contains("link"), "the symlink is reported: {}", text(&up));
    let listing = remote.fixture.shell(&format!("cd {}/top && find . -mindepth 1 | sort", remote.name));
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        [
            "./.hidden",
            "./a.txt",
            "./empty",
            "./sub",
            "./sub/b.bin",
            "./sub/deeper",
            "./sub/deeper/c",
            "./with space.txt"
        ]
    );

    let fresh = local.path().join("fresh");
    let down = scp(&remote.fixture, &["-r"], &[&remote.spec("top"), fresh.to_str().expect("utf-8")]);
    assert!(down.status.success(), "{}", text(&down));
    assert_eq!(tree(&fresh), expected);

    let into = local.path().join("into");
    fs::create_dir(&into).expect("into");
    let down = scp(&remote.fixture, &["-r"], &[&remote.spec("top"), into.to_str().expect("utf-8")]);
    assert!(down.status.success(), "{}", text(&down));
    assert_eq!(tree(&into.join("top")), expected);

    let several = local.path().join("several");
    fs::create_dir(&several).expect("several");
    let down = scp(
        &remote.fixture,
        &[],
        &[&remote.spec("top/a.txt"), &remote.spec("top/with space.txt"), several.to_str().expect("utf-8")],
    );
    assert!(down.status.success(), "{}", text(&down));
    assert_eq!(fs::read(several.join("with space.txt")).expect("read"), b"spaced");
}

fn set_times(path: &Path, modified: u64) {
    let file = fs::File::open(path).expect("open");
    let moment = SystemTime::UNIX_EPOCH + Duration::from_secs(modified);
    file.set_times(fs::FileTimes::new().set_accessed(moment).set_modified(moment))
        .expect("set times");
}

#[test]
fn preserve_keeps_mode_and_mtime_in_both_directions() {
    let remote = Remote::new("preserve");
    let local = tempfile::tempdir().expect("tempdir");
    let file = local.path().join("keep.txt");
    fs::write(&file, b"keep").expect("write");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("chmod");
    set_times(&file, 1_000_000_000);
    let plain = local.path().join("plain.txt");
    fs::write(&plain, b"plain").expect("write");
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o640)).expect("chmod");
    set_times(&plain, 1_000_000_000);

    let up = scp(&remote.fixture, &["-p"], &[file.to_str().expect("utf-8"), &remote.spec("keep.txt")]);
    assert!(up.status.success(), "{}", text(&up));
    assert_eq!(
        remote.fixture.shell(&format!("stat -c '%a %Y' {}", remote.path("keep.txt"))).trim(),
        "640 1000000000"
    );
    let up = scp(&remote.fixture, &[], &[plain.to_str().expect("utf-8"), &remote.spec("plain.txt")]);
    assert!(up.status.success(), "{}", text(&up));
    let unpreserved = remote.fixture.shell(&format!("stat -c '%Y' {}", remote.path("plain.txt")));
    assert_ne!(unpreserved.trim(), "1000000000", "without -p the time is the copy time");

    remote.fixture.shell(&format!(
        "mkdir -p {0}/dir/inner && echo x > {0}/dir/inner/f && chmod 600 {0}/dir/inner/f && touch -d @1234567890 {0}/dir/inner/f && chmod 750 {0}/dir/inner {0}/dir && touch -d @1234567891 {0}/dir/inner {0}/dir",
        remote.name
    ));
    let down = local.path().join("down");
    let result = scp(&remote.fixture, &["-r", "-p"], &[&remote.spec("dir"), down.to_str().expect("utf-8")]);
    assert!(result.status.success(), "{}", text(&result));
    let inner = fs::metadata(down.join("inner/f")).expect("file");
    assert_eq!((inner.permissions().mode() & 0o777, inner.mtime()), (0o600, 1_234_567_890));
    for directory in [down.clone(), down.join("inner")] {
        let metadata = fs::metadata(&directory).expect("dir");
        assert_eq!((metadata.permissions().mode() & 0o777, metadata.mtime()), (0o750, 1_234_567_891), "{directory:?}");
    }

    let single = local.path().join("single.txt");
    let result = scp(&remote.fixture, &["-p"], &[&remote.spec("keep.txt"), single.to_str().expect("utf-8")]);
    assert!(result.status.success(), "{}", text(&result));
    let metadata = fs::metadata(&single).expect("single");
    assert_eq!((metadata.permissions().mode() & 0o777, metadata.mtime()), (0o640, 1_000_000_000));
}

#[test]
fn a_batch_file_runs_every_command() {
    let remote = Remote::new("batch");
    let local = tempfile::tempdir().expect("tempdir");
    fs::write(local.path().join("up.txt"), b"uploaded\n").expect("write");
    fs::create_dir_all(local.path().join("tree/inner")).expect("tree");
    fs::write(local.path().join("tree/inner/leaf"), b"leaf").expect("leaf");
    let script = format!(
        "# comment\n\
         cd {name}\n\
         pwd\n\
         lpwd\n\
         mkdir made\n\
         put up.txt made/up.txt\n\
         put -r tree\n\
         ls made\n\
         ls -l made\n\
         cd made\n\
         get up.txt got.txt\n\
         rename up.txt moved.txt\n\
         ln -s moved.txt soft\n\
         ln moved.txt hard\n\
         chmod 600 moved.txt\n\
         df\n\
         df -h .\n\
         ls -a\n\
         lmkdir localdir\n\
         lcd localdir\n\
         get -r ../tree\n\
         lcd ..\n\
         -rm no-such-file\n\
         rm soft\n\
         rm hard\n\
         rm moved.txt\n\
         cd ..\n\
         rmdir made\n\
         bye\n\
         rm never-reached\n",
        name = remote.name
    );
    let output = sftp_batch(&remote.fixture, local.path(), &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", text(&output));
    assert!(stdout.contains(&format!("Remote working directory: /home/xinfra/{}", remote.name)), "{stdout}");
    assert!(stdout.contains(&format!("Local working directory: {}", local.path().display())), "{stdout}");
    assert!(stdout.contains("sftp> ls made\nup.txt\n"), "{stdout}");
    assert!(stdout.contains("-rw-r--r--"), "long listing: {stdout}");
    assert!(stdout.contains("%Capacity"), "df: {stdout}");
    assert!(!stdout.contains("never-reached"), "{stdout}");
    assert_eq!(fs::read(local.path().join("tree/inner/leaf")).expect("leaf"), b"leaf");
    assert_eq!(fs::read(local.path().join("localdir/tree/inner/leaf")).expect("downloaded"), b"leaf");
    assert_eq!(fs::read(local.path().join("got.txt")).expect("got.txt"), b"uploaded\n");
    let uploaded = remote.fixture.shell(&format!("ls {}", remote.name));
    assert!(uploaded.lines().any(|line| line == "tree"), "{uploaded}");
    assert!(!uploaded.lines().any(|line| line == "made"), "made was removed: {uploaded}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("no-such-file"), "{}", text(&output));
}

#[test]
fn a_batch_command_without_a_dash_aborts_the_batch() {
    let remote = Remote::new("abort");
    let local = tempfile::tempdir().expect("tempdir");
    let script = format!("cd {0}\nmkdir first\nrmdir missing\nmkdir second\n", remote.name);
    let output = sftp_batch(&remote.fixture, local.path(), &script);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing: No such file"), "{}", text(&output));
    let listing = remote.fixture.shell(&format!("ls {}", remote.name));
    assert_eq!(listing.lines().collect::<Vec<_>>(), ["first"]);
}

#[test]
fn a_wrong_host_key_is_refused_before_any_data() {
    let remote = Remote::new("pin");
    let local = tempfile::tempdir().expect("tempdir");
    let source = local.path().join("secret.txt");
    fs::write(&source, b"must not be sent").expect("write");

    let mut flags = remote.fixture.flags();
    let position = flags.iter().position(|flag| flag == "--host-key").expect("flag");
    flags[position + 1] = remote.fixture.other_pin.clone();

    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-scp"));
    command.args(&flags).arg(&source).arg(remote.spec("secret.txt"));
    let output = run(command);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("host key mismatch"), "{}", text(&output));
    assert!(remote.fixture.shell(&format!("ls {}", remote.name)).is_empty(), "nothing reached the server");

    let script = local.path().join("batch");
    fs::write(&script, format!("cd {}\nput secret.txt\n", remote.name)).expect("batch");
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-sftp"));
    command
        .current_dir(local.path())
        .args(&flags)
        .arg("-b")
        .arg(&script)
        .arg(remote.fixture.target());
    let output = run(command);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("host key mismatch"), "{}", text(&output));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sftp>"), "no command ran: {}", text(&output));
    assert!(remote.fixture.shell(&format!("ls {}", remote.name)).is_empty());
}

#[test]
fn a_missing_remote_file_is_a_nonzero_exit_with_a_message() {
    let remote = Remote::new("missing");
    let local = tempfile::tempdir().expect("tempdir");
    let target = local.path().join("never");
    let output = scp(&remote.fixture, &[], &[&remote.spec("no-such-file"), target.to_str().expect("utf-8")]);
    assert!(!output.status.success(), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no-such-file") && stderr.contains("No such file"), "{stderr}");
    assert!(!target.exists(), "no local file is created for a missing source");

    let source = local.path().join("exists.txt");
    fs::write(&source, b"x").expect("write");
    let output = scp(&remote.fixture, &[], &[source.to_str().expect("utf-8"), &remote.spec("no-dir/sub/target")]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No such file"), "{}", text(&output));

    let output = scp(&remote.fixture, &[], &[local.path().join("absent").to_str().expect("utf-8"), &remote.spec("x")]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("absent"), "{}", text(&output));

    let output = sftp_batch(&remote.fixture, local.path(), "get no-such-file\n");
    assert!(!output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No such file"), "{}", text(&output));
}

#[test]
fn the_library_covers_the_whole_command_set() {
    let remote = Remote::new("api");
    let mut sftp = remote.fixture.sftp();
    assert_eq!(sftp.version(), 3);
    for extension in ["posix-rename@openssh.com", "limits@openssh.com", "statvfs@openssh.com", "fsync@openssh.com", "hardlink@openssh.com"] {
        assert!(sftp.has_extension(extension), "{extension} in {:?}", sftp.extensions());
    }
    let limits = sftp.limits();
    assert!(limits.read_len >= 32 * 1024 && limits.read_len <= oxish_client::sftp::MAX_BLOCK, "{limits:?}");

    let home = sftp.realpath(b".").expect("realpath");
    let base = format!("{}/{}", String::from_utf8_lossy(&home), remote.name).into_bytes();
    let path = |tail: &str| [base.clone(), b"/".to_vec(), tail.as_bytes().to_vec()].concat();

    sftp.mkdir(path("d"), &Attrs::with_permissions(0o755)).expect("mkdir");
    let handle = sftp
        .open(path("d/f"), OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE, &Attrs::with_permissions(0o600))
        .expect("open");
    sftp.write(&handle, 0, b"hello ").expect("write");
    sftp.write(&handle, 6, b"world").expect("write");
    sftp.fsync(&handle).expect("fsync");
    assert_eq!(sftp.fstat(&handle).expect("fstat").size, Some(11));
    sftp.fsetstat(&handle, &Attrs { times: Some((1_000_000_000, 1_000_000_001)), ..Attrs::default() }).expect("fsetstat");
    assert_eq!(sftp.read(&handle, 3, 100).expect("read"), b"lo world");
    assert!(sftp.read(&handle, 11, 10).expect("eof").is_empty());
    let stats = sftp.fstatvfs(&handle).expect("fstatvfs");
    assert!(stats.blocks > 0 && stats.name_max > 0);
    sftp.close_handle(&handle).expect("close");

    let attrs = sftp.stat(path("d/f")).expect("stat");
    assert!(attrs.is_regular());
    assert_eq!((attrs.size, attrs.permissions.map(|mode| mode & 0o777), attrs.times.map(|(_, modified)| modified)), (Some(11), Some(0o600), Some(1_000_000_001)));
    sftp.setstat(path("d/f"), &Attrs::with_permissions(0o644)).expect("setstat");
    assert_eq!(sftp.stat(path("d/f")).expect("stat").permissions.map(|mode| mode & 0o777), Some(0o644));

    sftp.symlink(b"f", path("d/link")).expect("symlink");
    assert_eq!(sftp.readlink(path("d/link")).expect("readlink"), b"f");
    assert!(sftp.lstat(path("d/link")).expect("lstat").is_symlink());
    assert!(sftp.stat(path("d/link")).expect("stat through").is_regular());
    sftp.hardlink(path("d/f"), path("d/hard")).expect("hardlink");
    let other = sftp.open(path("d/g"), OpenFlags::WRITE | OpenFlags::CREATE, &Attrs::default()).expect("create g");
    sftp.write(&other, 0, b"g").expect("write g");
    sftp.close_handle(&other).expect("close g");
    sftp.rename(path("d/g"), path("d/f")).expect("posix rename replaces");
    assert_eq!(sftp.stat(path("d/f")).expect("stat").size, Some(1));

    let mut names: Vec<_> = sftp.read_dir(path("d")).expect("read_dir").into_iter().map(|entry| entry.name).filter(|name| name[0] != b'.').collect();
    names.sort();
    assert_eq!(names, [b"f".to_vec(), b"hard".to_vec(), b"link".to_vec()]);
    assert!(sftp.statvfs(path("d")).expect("statvfs").blocks > 0);

    match sftp.stat(path("missing")) {
        Err(SftpError::Status { code, .. }) => assert_eq!(code, STATUS_NO_SUCH_FILE),
        other => panic!("expected a status error, got {other:?}"),
    }
    assert!(sftp.rmdir(path("d")).is_err(), "not empty");
    sftp.remove(path("d/link")).expect("remove");
    sftp.remove(path("d/hard")).expect("remove");
    sftp.remove(path("d/f")).expect("remove");
    sftp.rmdir(path("d")).expect("rmdir");
    assert!(sftp.opendir(path("d")).is_err());
    sftp.disconnect();
}

fn delayed_proxy(target_port: u16, one_way: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    let port = listener.local_addr().expect("address").port();
    thread::spawn(move || {
        let Ok((client, _)) = listener.accept() else { return };
        let server = TcpStream::connect(("127.0.0.1", target_port)).expect("proxy upstream");
        for (mut from, mut to) in [
            (client.try_clone().expect("clone"), server.try_clone().expect("clone")),
            (server, client),
        ] {
            let (sender, receiver) = mpsc::channel::<(Instant, Vec<u8>)>();
            thread::spawn(move || {
                let mut buffer = vec![0u8; 64 * 1024];
                while let Ok(count) = from.read(&mut buffer) {
                    if count == 0 || sender.send((Instant::now(), buffer[..count].to_vec())).is_err() {
                        break;
                    }
                }
            });
            thread::spawn(move || {
                let mut queue = VecDeque::new();
                while let Ok(item) = receiver.recv() {
                    queue.push_back(item);
                    while let Some((arrived, bytes)) = queue.pop_front() {
                        let due = arrived + one_way;
                        if let Some(wait) = due.checked_duration_since(Instant::now()) {
                            thread::sleep(wait);
                        }
                        if to.write_all(&bytes).is_err() {
                            return;
                        }
                    }
                }
                let _ = to.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    port
}

fn throughput_round_trip(sftp: &mut Sftp, remote_path: &[u8], content: &[u8]) -> (Duration, Duration) {
    let handle = sftp
        .open(remote_path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE, &Attrs::default())
        .expect("open for write");
    let started = Instant::now();
    let mut reader = content;
    let written = sftp.upload(&handle, 0, &mut reader, &mut |_| {}).expect("upload");
    assert_eq!(written as usize, content.len());
    sftp.close_handle(&handle).expect("close");
    let upload = started.elapsed();

    let size = sftp.stat(remote_path).expect("stat").size;
    assert_eq!(size, Some(content.len() as u64));
    let handle = sftp.open(remote_path, OpenFlags::READ, &Attrs::default()).expect("open for read");
    let started = Instant::now();
    let mut downloaded = Vec::with_capacity(content.len());
    let read = sftp.download(&handle, 0, size, &mut downloaded, &mut |_| {}).expect("download");
    assert_eq!(read as usize, content.len());
    sftp.close_handle(&handle).expect("close");
    let download = started.elapsed();
    assert!(downloaded == content, "the downloaded bytes differ");
    (upload, download)
}

#[test]
fn fifty_mib_transfers_quickly() {
    let remote = Remote::new("speed");
    let content = pseudo_random(50 * 1024 * 1024, 11);
    let mut sftp = remote.fixture.sftp();
    let home = String::from_utf8(sftp.realpath(b".").expect("home")).expect("utf-8");
    let path = format!("{home}/{}/big", remote.name);
    let (upload, download) = throughput_round_trip(&mut sftp, path.as_bytes(), &content);
    eprintln!("50 MiB over loopback: upload {upload:?}, download {download:?}");
    assert!(upload < Duration::from_secs(60), "upload took {upload:?}");
    assert!(download < Duration::from_secs(60), "download took {download:?}");
    assert_eq!(remote_sum(&remote.fixture, &remote.path("big")), hex(&content));
    sftp.disconnect();
}

#[test]
fn requests_are_pipelined_not_serialized_per_round_trip() {
    let remote = Remote::new("latency");
    let content = pseudo_random(50 * 1024 * 1024, 13);
    let one_way = Duration::from_millis(10);
    let port = delayed_proxy(remote.fixture.port.parse().expect("port"), one_way);
    let mut sftp = Sftp::connect(remote.fixture.connection_to(&port.to_string()), None).expect("sftp over the delayed link");
    let home = String::from_utf8(sftp.realpath(b".").expect("home")).expect("utf-8");
    let path = format!("{home}/{}/slow", remote.name);
    let (upload, download) = throughput_round_trip(&mut sftp, path.as_bytes(), &content);
    let round_trip = one_way * 2;
    let requests = content.len() / oxish_client::sftp::DEFAULT_BLOCK;
    let serialized = round_trip * requests as u32;
    eprintln!("50 MiB at {round_trip:?} round trip: upload {upload:?}, download {download:?}; serialized would take at least {serialized:?}");
    assert!(upload < serialized / 2, "upload took {upload:?}, one round trip per request would be {serialized:?}");
    assert!(download < serialized / 2, "download took {download:?}, one round trip per request would be {serialized:?}");
    sftp.disconnect();
}

#[test]
fn progress_is_drawn_on_a_terminal() {
    use rustix::fs::{Mode, OFlags, open};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    let remote = Remote::new("tty");
    let local = tempfile::tempdir().expect("tempdir");
    let source = local.path().join("shown.bin");
    fs::write(&source, pseudo_random(3 * 1024 * 1024, 5)).expect("write");

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("pty master");
    grantpt(&master).expect("grant");
    unlockpt(&master).expect("unlock");
    let name = ptsname(&master, Vec::new()).expect("slave name");
    let slave = open(name.as_c_str(), OFlags::RDWR | OFlags::NOCTTY, Mode::empty()).expect("pty slave");
    let mut master = fs::File::from(master);
    let collector = thread::spawn(move || {
        let mut screen = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(count) = master.read(&mut buffer) {
            if count == 0 {
                break;
            }
            screen.extend_from_slice(&buffer[..count]);
        }
        screen
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-scp"));
    command
        .args(remote.fixture.flags())
        .arg(&source)
        .arg(remote.spec("shown.bin"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(slave.try_clone().expect("dup")))
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    drop(command);
    drop(slave);
    let status = child.wait().expect("wait");
    assert!(status.success());
    let screen = String::from_utf8_lossy(&collector.join().expect("collector")).into_owned();
    assert!(screen.contains("shown.bin") && screen.contains("100%") && screen.contains("MB/s"), "{screen:?}");
}

#[test]
fn a_session_survives_idle_time_between_commands() {
    use std::io::BufRead;

    let remote = Remote::new("idle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxish-sftp"));
    command
        .args(remote.fixture.flags())
        .arg(remote.fixture.target())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    let mut input = child.stdin.take().expect("stdin");
    let mut output = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    writeln!(input, "pwd").expect("pwd");
    input.flush().expect("flush");
    output.read_line(&mut line).expect("first answer");
    assert!(line.starts_with("Remote working directory: /"), "{line}");
    thread::sleep(Duration::from_secs(3));
    writeln!(input, "mkdir {}", remote.name.clone() + "/after-idle").expect("mkdir");
    writeln!(input, "pwd").expect("pwd");
    input.flush().expect("flush");
    line.clear();
    output.read_line(&mut line).expect("second answer");
    assert!(line.starts_with("Remote working directory: /"), "{line}");
    drop(input);
    let status = child.wait().expect("wait");
    assert!(status.success());
    assert_eq!(remote.fixture.shell(&format!("ls {}", remote.name)).trim(), "after-idle");
}
