use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
    path::Path,
};

use tempfile::TempDir;

use crate::sftp::{
    Attrs, Core, Engine, Fatal, MAX_BUFFERED_INPUT, MAX_DATA, MAX_HANDLES, MAX_PACKET, MAX_PENDING, Owner, Status,
    long_name,
};

const OK: u32 = 0;
const EOF: u32 = 1;
const NO_SUCH_FILE: u32 = 2;
const PERMISSION_DENIED: u32 = 3;
const FAILURE: u32 = 4;
const BAD_MESSAGE: u32 = 5;
const OP_UNSUPPORTED: u32 = 8;

const READ: u32 = 1;
const WRITE: u32 = 2;
const APPEND: u32 = 4;
const CREATE: u32 = 8;
const TRUNCATE: u32 = 16;
const EXCLUSIVE: u32 = 32;

fn u32s(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn u64s(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn string(value: impl AsRef<[u8]>) -> Vec<u8> {
    let value = value.as_ref();
    [u32s(value.len() as u32), value.to_vec()].concat()
}

fn attrs(attrs: &Attrs) -> Vec<u8> {
    let mut flags = 0;
    let mut body = Vec::new();
    if let Some(size) = attrs.size {
        flags |= 1;
        body.extend(u64s(size));
    }
    if let Some((uid, gid)) = attrs.owner {
        flags |= 2;
        body.extend([u32s(uid), u32s(gid)].concat());
    }
    if let Some(permissions) = attrs.permissions {
        flags |= 4;
        body.extend(u32s(permissions));
    }
    if let Some((atime, mtime)) = attrs.times {
        flags |= 8;
        body.extend([u32s(atime), u32s(mtime)].concat());
    }
    [u32s(flags), body].concat()
}

fn no_attrs() -> Vec<u8> {
    u32s(0)
}

fn permissions(mode: u32) -> Vec<u8> {
    attrs(&Attrs { permissions: Some(mode), ..Attrs::default() })
}

fn packet(kind: u8, body: &[u8]) -> Vec<u8> {
    [u32s(body.len() as u32 + 1), vec![kind], body.to_vec()].concat()
}

struct Response {
    kind: u8,
    id: u32,
    body: Vec<u8>,
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn u32(&mut self) -> u32 {
        let (head, rest) = self.0.split_at(4);
        self.0 = rest;
        u32::from_be_bytes(head.try_into().unwrap())
    }

    fn u64(&mut self) -> u64 {
        let (head, rest) = self.0.split_at(8);
        self.0 = rest;
        u64::from_be_bytes(head.try_into().unwrap())
    }

    fn string(&mut self) -> Vec<u8> {
        let len = self.u32() as usize;
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        head.to_vec()
    }

    fn attrs(&mut self) -> Attrs {
        let flags = self.u32();
        let mut attrs = Attrs::default();
        if flags & 1 != 0 {
            attrs.size = Some(self.u64());
        }
        if flags & 2 != 0 {
            attrs.owner = Some((self.u32(), self.u32()));
        }
        if flags & 4 != 0 {
            attrs.permissions = Some(self.u32());
        }
        if flags & 8 != 0 {
            attrs.times = Some((self.u32(), self.u32()));
        }
        attrs
    }
}

impl Response {
    fn cursor(&self) -> Cursor<'_> {
        Cursor(&self.body)
    }

    fn status(&self) -> u32 {
        assert_eq!(self.kind, 101, "not a status reply: type {}", self.kind);
        self.cursor().u32()
    }

    fn handle(&self) -> Vec<u8> {
        assert_eq!(self.kind, 102, "not a handle: type {} status {}", self.kind, self.body.get(3).copied().unwrap_or(0));
        self.cursor().string()
    }

    fn data(&self) -> Vec<u8> {
        assert_eq!(self.kind, 103, "not data: type {} status {}", self.kind, self.body.get(3).copied().unwrap_or(0));
        self.cursor().string()
    }

    fn attrs(&self) -> Attrs {
        assert_eq!(self.kind, 105, "not attributes: type {}", self.kind);
        self.cursor().attrs()
    }

    fn names(&self) -> Vec<(String, String, Attrs)> {
        assert_eq!(self.kind, 104, "not names: type {}", self.kind);
        let mut cursor = self.cursor();
        (0..cursor.u32())
            .map(|_| {
                let name = String::from_utf8_lossy(&cursor.string()).into_owned();
                let long = String::from_utf8_lossy(&cursor.string()).into_owned();
                (name, long, cursor.attrs())
            })
            .collect()
    }

    fn name(&self) -> String {
        let names = self.names();
        assert_eq!(names.len(), 1);
        names[0].0.clone()
    }
}

struct Session {
    dir: TempDir,
    core: Core,
    next: u32,
}

fn owner() -> Owner {
    Owner { uid: rustix::process::geteuid().as_raw(), name: "alice".into() }
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

impl Session {
    fn raw() -> Self {
        let dir = TempDir::new().unwrap();
        let home = fs::canonicalize(dir.path()).unwrap();
        let core = Core::new(Engine::new(&home, owner()).unwrap());
        Self { dir, core, next: 1 }
    }

    fn new() -> Self {
        let mut session = Self::raw();
        let init = session.exchange(&packet(1, &u32s(3))).remove(0);
        assert_eq!(init.kind, 2);
        session
    }

    fn path(&self, name: &str) -> String {
        self.home().join(name).display().to_string()
    }

    fn home(&self) -> std::path::PathBuf {
        fs::canonicalize(self.dir.path()).unwrap()
    }

    fn exchange(&mut self, bytes: &[u8]) -> Vec<Response> {
        self.core.push(bytes).unwrap();
        let mut out = Vec::new();
        loop {
            let consumed = self.core.run().unwrap();
            let chunk = self.core.output(usize::MAX).to_vec();
            self.core.sent(chunk.len());
            out.extend(chunk);
            if consumed == 0 && !self.core.has_output() {
                break;
            }
        }
        let mut responses = Vec::new();
        let mut rest = out.as_slice();
        while !rest.is_empty() {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let body = &rest[5..4 + len];
            let kind = rest[4];
            let (id, body) = match kind {
                2 => (0, body.to_vec()),
                _ => (u32::from_be_bytes(body[..4].try_into().unwrap()), body[4..].to_vec()),
            };
            responses.push(Response { kind, id, body });
            rest = &rest[4 + len..];
        }
        responses
    }

    fn call(&mut self, kind: u8, body: &[u8]) -> Response {
        let id = self.next;
        self.next += 1;
        let mut responses = self.exchange(&packet(kind, &[u32s(id), body.to_vec()].concat()));
        assert_eq!(responses.len(), 1);
        let response = responses.remove(0);
        assert_eq!(response.id, id);
        response
    }

    fn extended(&mut self, name: &str, body: &[u8]) -> Response {
        self.call(200, &[string(name), body.to_vec()].concat())
    }

    fn open(&mut self, name: &str, flags: u32) -> Vec<u8> {
        self.call(3, &[string(self.path(name)), u32s(flags), no_attrs()].concat()).handle()
    }

    fn close(&mut self, handle: &[u8]) {
        assert_eq!(self.call(4, &string(handle)).status(), OK);
    }

    fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> u32 {
        self.call(6, &[string(handle), u64s(offset), string(data)].concat()).status()
    }

    fn read(&mut self, handle: &[u8], offset: u64, len: u32) -> Response {
        self.call(5, &[string(handle), u64s(offset), u32s(len)].concat())
    }

    fn put(&mut self, name: &str, contents: &[u8]) {
        let handle = self.open(name, WRITE | CREATE | TRUNCATE);
        assert_eq!(self.write(&handle, 0, contents), OK);
        self.close(&handle);
    }

    fn status_of(&mut self, kind: u8, body: &[u8]) -> u32 {
        self.call(kind, body).status()
    }
}

#[test]
fn the_version_exchange_lists_the_extensions() {
    let mut session = Session::raw();
    let mut extra = string("extra");
    extra.extend(string("1"));
    let hello = [u32s(6), extra].concat();
    let reply = session.exchange(&packet(1, &hello)).remove(0);
    assert_eq!(reply.kind, 2);
    let mut cursor = reply.cursor();
    assert_eq!(cursor.u32(), 3);
    let mut names = Vec::new();
    while !cursor.0.is_empty() {
        names.push(String::from_utf8(cursor.string()).unwrap());
        cursor.string();
    }
    for expected in [
        "posix-rename@openssh.com",
        "statvfs@openssh.com",
        "fstatvfs@openssh.com",
        "hardlink@openssh.com",
        "fsync@openssh.com",
        "lsetstat@openssh.com",
        "limits@openssh.com",
        "expand-path@openssh.com",
    ] {
        assert!(names.iter().any(|name| name == expected), "{expected} missing from {names:?}");
    }
}

#[test]
fn requests_before_the_version_exchange_and_a_second_one_are_refused() {
    let mut session = Session::raw();
    session.core.push(&packet(17, &[u32s(1), string(".")].concat())).unwrap();
    assert_eq!(session.core.run(), Err(Fatal("request before the version exchange")));

    let mut session = Session::new();
    session.core.push(&packet(1, &u32s(3))).unwrap();
    assert_eq!(session.core.run(), Err(Fatal("second version exchange")));
}

#[test]
fn malformed_packets_are_fatal() {
    for (kind, body) in [
        (17, u32s(1)),
        (17, [u32s(1), u32s(100), b"short".to_vec()].concat()),
        (3, [u32s(1), string("x")].concat()),
        (3, [u32s(1), string("x"), u32s(1), u32s(0x10)].concat()),
        (9, [u32s(1), string("x"), u32s(3)].concat()),
        (5, [u32s(1), string("12345678"), u64s(0)].concat()),
        (6, [u32s(1), string("12345678"), u64s(0), u32s(1000)].concat()),
        (200, [u32s(1), u32s(500)].concat()),
        (4, Vec::new()),
    ] {
        let mut session = Session::new();
        session.core.push(&packet(kind, &body)).unwrap();
        assert!(session.core.run().is_err(), "type {kind} with {body:?} was accepted");
    }
}

#[test]
fn bad_length_prefixes_and_oversized_input_are_refused_when_they_arrive() {
    let mut session = Session::new();
    assert!(session.core.push(&u32s(0)).is_err());
    let mut session = Session::new();
    assert!(session.core.push(&u32s(MAX_PACKET as u32 + 1)).is_err());
    let mut session = Session::new();
    assert!(session.core.push(&u32s(MAX_PACKET as u32)).is_ok(), "the largest packet is accepted");

    let mut session = Session::new();
    let mut flood = Vec::new();
    for _ in 0..=MAX_PENDING {
        flood.extend(packet(17, &[u32s(1), string("x")].concat()));
    }
    assert!(session.core.push(&flood).is_err(), "too many queued requests");

    let mut session = Session::new();
    let whole = [u32s(MAX_PACKET as u32), vec![0; MAX_PACKET]].concat();
    for _ in 0..3 {
        assert!(session.core.push(&whole).is_ok());
    }
    let room = MAX_BUFFERED_INPUT - 3 * whole.len();
    assert!(session.core.push(&[u32s(MAX_PACKET as u32), vec![0; room - 4]].concat()).is_ok());
    assert!(session.core.push(&[0]).is_err(), "more unprocessed bytes than the window");
}

#[test]
fn requests_are_executed_in_bounded_batches_and_output_is_bounded() {
    let mut session = Session::new();
    session.put("big", &vec![7; MAX_DATA]);
    let handle = session.open("big", READ);
    let mut flood = Vec::new();
    for id in 0..200_u32 {
        flood.extend(packet(5, &[u32s(id), string(&handle), u64s(0), u32s(MAX_DATA as u32)].concat()));
    }
    session.core.push(&flood).unwrap();
    let consumed = session.core.run().unwrap();
    assert!(consumed > 0 && consumed < flood.len(), "all {} requests ran at once ({consumed})", 200);
    assert!(session.core.output(usize::MAX).len() <= 3 * MAX_PACKET, "output grew past its budget");
    let first = session.core.output(usize::MAX).len();
    session.core.sent(first);
    assert!(session.core.run().unwrap() > 0, "sending output lets requests continue");
}

#[test]
fn files_are_written_read_and_ended_with_eof() {
    let mut session = Session::new();
    let handle = session.open("a.txt", WRITE | CREATE | EXCLUSIVE);
    assert_eq!(session.write(&handle, 0, b"hello "), OK);
    assert_eq!(session.write(&handle, 6, b"world"), OK);
    assert_eq!(session.read(&handle, 0, 5).status(), NO_SUCH_FILE, "reading a write-only handle");
    session.close(&handle);
    assert_eq!(fs::read(session.home().join("a.txt")).unwrap(), b"hello world");

    let created = fs::metadata(session.home().join("a.txt")).unwrap().permissions().mode() & 0o777;
    assert_eq!(created & 0o600, 0o600, "the default mode is 0666 less the umask");
    assert_eq!(created & 0o111, 0);

    let again = session.call(3, &[string(session.path("a.txt")), u32s(WRITE | CREATE | EXCLUSIVE), no_attrs()].concat());
    assert_eq!(again.status(), FAILURE, "exclusive create of an existing file");

    let handle = session.open("a.txt", READ);
    assert_eq!(session.read(&handle, 0, 5).data(), b"hello");
    assert_eq!(session.read(&handle, 6, 100).data(), b"world");
    assert_eq!(session.read(&handle, 11, 10).status(), EOF);
    assert_eq!(session.read(&handle, 1 << 40, 10).status(), EOF);
    assert_eq!(session.write(&handle, 0, b"x"), NO_SUCH_FILE, "writing a read-only handle");
    session.close(&handle);

    let handle = session.open("a.txt", WRITE | TRUNCATE);
    session.close(&handle);
    assert_eq!(fs::metadata(session.home().join("a.txt")).unwrap().len(), 0);

    let handle = session.open("a.txt", WRITE | APPEND);
    assert_eq!(session.write(&handle, 0, b"one"), OK);
    assert_eq!(session.write(&handle, 0, b"two"), OK);
    session.close(&handle);
    assert_eq!(fs::read(session.home().join("a.txt")).unwrap(), b"onetwo");

    let handle = session.open("a.txt", READ | WRITE);
    assert_eq!(session.write(&handle, 10, b"!"), OK);
    session.close(&handle);
    assert_eq!(fs::read(session.home().join("a.txt")).unwrap(), b"onetwo\0\0\0\0!");
}

#[test]
fn created_files_take_the_requested_mode() {
    let mut session = Session::new();
    let path = session.path("m");
    let handle = session
        .call(3, &[string(path), u32s(WRITE | CREATE), permissions(0o600)].concat())
        .handle();
    session.close(&handle);
    assert_eq!(fs::metadata(session.home().join("m")).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn reads_are_capped_and_large_transfers_round_trip() {
    let mut session = Session::new();
    let data: Vec<u8> = (0..MAX_DATA * 2 + 17).map(|index| (index % 251) as u8).collect();
    let handle = session.open("large", WRITE | CREATE);
    for (index, chunk) in data.chunks(MAX_DATA).enumerate() {
        assert_eq!(session.write(&handle, (index * MAX_DATA) as u64, chunk), OK);
    }
    session.close(&handle);

    let handle = session.open("large", READ);
    let first = session.read(&handle, 0, u32::MAX).data();
    assert_eq!(first.len(), MAX_DATA, "a read is capped at the advertised length");
    let mut all = first;
    while all.len() < data.len() {
        let next = session.read(&handle, all.len() as u64, 65536);
        all.extend(next.data());
    }
    assert_eq!(all, data);
    assert_eq!(session.read(&handle, 0, 0).data().len(), 0);
}

#[test]
fn stat_family_reports_attributes_and_follows_links_only_when_asked() {
    let mut session = Session::new();
    session.put("file", b"12345");
    symlink("file", session.home().join("link")).unwrap();
    fs::set_permissions(session.home().join("file"), fs::Permissions::from_mode(0o640)).unwrap();

    let stat = session.call(17, &string(session.path("file"))).attrs();
    assert_eq!(stat.size, Some(5));
    assert_eq!(stat.permissions.unwrap() & 0o7777, 0o640);
    assert_eq!(stat.permissions.unwrap() & 0o170_000, 0o100_000);
    let meta = fs::metadata(session.home().join("file")).unwrap();
    assert_eq!(stat.owner, Some((meta.uid(), meta.gid())));
    assert_eq!(stat.times.unwrap().1 as i64, meta.mtime());

    let through = session.call(17, &string(session.path("link"))).attrs();
    assert_eq!(through.size, Some(5));
    let link = session.call(7, &string(session.path("link"))).attrs();
    assert_eq!(link.permissions.unwrap() & 0o170_000, 0o120_000, "lstat reports the link itself");
    assert_ne!(link.size, Some(5));

    assert_eq!(session.call(17, &string(session.path("missing"))).status(), NO_SUCH_FILE);
    assert_eq!(session.call(7, &string(session.path("missing/deeper"))).status(), NO_SUCH_FILE);

    let handle = session.open("file", READ);
    assert_eq!(session.call(8, &string(&handle)).attrs().size, Some(5));
    session.close(&handle);
    assert_eq!(session.call(8, &string(&handle)).status(), FAILURE, "a closed handle");
}

#[test]
fn setstat_changes_mode_size_times_and_owner() {
    let mut session = Session::new();
    session.put("f", b"0123456789");
    let path = session.path("f");
    let meta = fs::metadata(session.home().join("f")).unwrap();

    let change = Attrs {
        size: Some(4),
        permissions: Some(0o600),
        times: Some((1_000_000, 2_000_000)),
        owner: Some((meta.uid(), meta.gid())),
    };
    assert_eq!(session.status_of(9, &[string(&path), attrs(&change)].concat()), OK);
    let meta = fs::metadata(session.home().join("f")).unwrap();
    assert_eq!((meta.len(), meta.permissions().mode() & 0o7777), (4, 0o600));
    assert_eq!((meta.atime(), meta.mtime()), (1_000_000, 2_000_000));

    let handle = session.open("f", READ | WRITE);
    let change = Attrs { size: Some(2), permissions: Some(0o640), times: Some((3_000_000, 4_000_000)), owner: None };
    assert_eq!(session.status_of(10, &[string(&handle), attrs(&change)].concat()), OK);
    session.close(&handle);
    let meta = fs::metadata(session.home().join("f")).unwrap();
    assert_eq!((meta.len(), meta.permissions().mode() & 0o7777), (2, 0o640));
    assert_eq!(meta.mtime(), 4_000_000);

    assert_eq!(session.status_of(9, &[string(session.path("missing")), permissions(0o600)].concat()), NO_SUCH_FILE);
    if !is_root() {
        let other = Attrs { owner: Some((meta.uid() + 1, meta.gid())), ..Attrs::default() };
        assert_eq!(session.status_of(9, &[string(&path), attrs(&other)].concat()), PERMISSION_DENIED);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lsetstat_never_follows_a_link() {
    let mut session = Session::new();
    session.put("target", b"x");
    fs::set_permissions(session.home().join("target"), fs::Permissions::from_mode(0o644)).unwrap();
    symlink("target", session.home().join("link")).unwrap();
    let link = session.path("link");

    let times = Attrs { times: Some((5_000_000, 6_000_000)), ..Attrs::default() };
    assert_eq!(session.extended("lsetstat@openssh.com", &[string(&link), attrs(&times)].concat()).status(), OK);
    let target = fs::metadata(session.home().join("target")).unwrap();
    assert_ne!(target.mtime(), 6_000_000, "the target of the link was changed");
    assert_eq!(fs::symlink_metadata(session.home().join("link")).unwrap().mtime(), 6_000_000);

    let size = Attrs { size: Some(0), ..Attrs::default() };
    assert_eq!(
        session.extended("lsetstat@openssh.com", &[string(&link), attrs(&size)].concat()).status(),
        OP_UNSUPPORTED
    );
    assert_eq!(fs::metadata(session.home().join("target")).unwrap().len(), 1);

    let mode = permissions(0o600);
    let reply = session.extended("lsetstat@openssh.com", &[string(&link), mode.clone()].concat()).status();
    assert_ne!(reply, OK, "a link's mode cannot change on Linux");
    assert_eq!(fs::metadata(session.home().join("target")).unwrap().permissions().mode() & 0o777, 0o644);

    session.put("plain", b"y");
    assert_eq!(
        session.extended("lsetstat@openssh.com", &[string(session.path("plain")), mode].concat()).status(),
        OK
    );
    assert_eq!(fs::metadata(session.home().join("plain")).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn directories_are_listed_with_dots_long_names_and_an_end() {
    let mut session = Session::new();
    session.put("one", b"1");
    fs::create_dir(session.home().join("sub")).unwrap();
    symlink("one", session.home().join("ln")).unwrap();
    let handle = session.call(11, &string(session.path(""))).handle();

    let mut seen = Vec::new();
    loop {
        let reply = session.call(12, &string(&handle));
        if reply.kind == 101 {
            assert_eq!(reply.status(), EOF);
            break;
        }
        seen.extend(reply.names());
    }
    let mut names: Vec<&str> = seen.iter().map(|(name, _, _)| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, [".", "..", "ln", "one", "sub"]);
    let line = |name: &str| seen.iter().find(|entry| entry.0 == name).unwrap().1.clone();
    assert!(line("one").starts_with("-rw"), "{}", line("one"));
    assert!(line("one").contains(" alice "), "{}", line("one"));
    assert!(line("one").ends_with(" one"));
    assert!(line("sub").starts_with("drwx"), "{}", line("sub"));
    assert!(line("ln").starts_with("lrwx"), "{}", line("ln"));
    let attrs = &seen.iter().find(|entry| entry.0 == "one").unwrap().2;
    assert_eq!(attrs.size, Some(1));
    assert_eq!(session.call(12, &string(&handle)).status(), EOF, "the end stays the end");
    session.close(&handle);

    let file = session.open("one", READ);
    assert_eq!(session.call(12, &string(&file)).status(), FAILURE, "readdir on a file handle");
    assert_eq!(session.read(&handle, 0, 1).status(), FAILURE, "closed handle");
    assert_eq!(session.call(11, &string(session.path("one"))).status(), NO_SUCH_FILE, "opendir on a file");
    assert_eq!(session.call(3, &[string(session.path("sub")), u32s(READ), no_attrs()].concat()).status(), FAILURE);
}

#[test]
fn large_directories_are_listed_in_several_replies() {
    let mut session = Session::new();
    fs::create_dir(session.home().join("many")).unwrap();
    for index in 0..250 {
        fs::write(session.home().join("many").join(format!("file-{index:03}")), b"").unwrap();
    }
    let handle = session.call(11, &string(session.path("many"))).handle();
    let (mut replies, mut total) = (0, 0);
    loop {
        let reply = session.call(12, &string(&handle));
        if reply.kind == 101 {
            break;
        }
        replies += 1;
        total += reply.names().len();
    }
    assert_eq!(total, 252);
    assert!(replies >= 3, "{replies} replies");
}

#[test]
fn files_and_directories_are_made_and_removed() {
    let mut session = Session::new();
    let dir = session.path("d");
    assert_eq!(session.status_of(14, &[string(&dir), permissions(0o700)].concat()), OK);
    assert_eq!(fs::metadata(session.home().join("d")).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(session.status_of(14, &[string(&dir), no_attrs()].concat()), FAILURE, "mkdir over an existing one");
    assert_eq!(session.status_of(14, &[string(session.path("x/y")), no_attrs()].concat()), NO_SUCH_FILE);

    session.put("d/f", b"x");
    assert_eq!(session.status_of(15, &string(&dir)), FAILURE, "rmdir of a directory with content");
    assert_eq!(session.status_of(13, &string(&dir)), FAILURE, "remove of a directory");
    assert_eq!(session.status_of(13, &string(session.path("d/f"))), OK);
    assert_eq!(session.status_of(13, &string(session.path("d/f"))), NO_SUCH_FILE);
    assert_eq!(session.status_of(15, &string(&dir)), OK);
    assert!(!session.home().join("d").exists());
    assert_eq!(session.status_of(15, &string(&dir)), NO_SUCH_FILE);

    if !is_root() {
        fs::create_dir(session.home().join("locked")).unwrap();
        fs::write(session.home().join("locked/f"), b"").unwrap();
        fs::set_permissions(session.home().join("locked"), fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(session.status_of(13, &string(session.path("locked/f"))), PERMISSION_DENIED);
        let reply = session.call(3, &[string(session.path("locked/new")), u32s(WRITE | CREATE), no_attrs()].concat());
        assert_eq!(reply.status(), PERMISSION_DENIED);
        fs::set_permissions(session.home().join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn rename_refuses_to_replace_but_posix_rename_replaces() {
    let mut session = Session::new();
    session.put("a", b"A");
    session.put("b", b"B");
    let (a, b, c) = (session.path("a"), session.path("b"), session.path("c"));
    assert_eq!(session.status_of(18, &[string(&a), string(&b)].concat()), FAILURE);
    assert_eq!(fs::read(session.home().join("b")).unwrap(), b"B");
    assert_eq!(session.status_of(18, &[string(&a), string(&c)].concat()), OK);
    assert!(!session.home().join("a").exists());
    assert_eq!(fs::read(session.home().join("c")).unwrap(), b"A");
    assert_eq!(session.status_of(18, &[string(&a), string(&c)].concat()), NO_SUCH_FILE);

    let reply = session.extended("posix-rename@openssh.com", &[string(&c), string(&b)].concat());
    assert_eq!(reply.status(), OK);
    assert_eq!(fs::read(session.home().join("b")).unwrap(), b"A");
    assert!(!session.home().join("c").exists());

    fs::create_dir(session.home().join("dir")).unwrap();
    let dir = session.path("dir");
    let moved = session.path("dir2");
    assert_eq!(session.status_of(18, &[string(&dir), string(&moved)].concat()), OK);
    assert!(session.home().join("dir2").is_dir());
}

#[test]
fn links_are_made_and_read_in_openssh_argument_order() {
    let mut session = Session::new();
    session.put("real", b"data");
    let link = session.path("l");
    assert_eq!(session.status_of(20, &[string("real"), string(&link)].concat()), OK);
    assert_eq!(fs::read_link(session.home().join("l")).unwrap(), Path::new("real"));
    assert_eq!(session.call(19, &string(&link)).name(), "real");
    assert_eq!(session.status_of(20, &[string("real"), string(&link)].concat()), FAILURE, "an existing link");
    assert_eq!(session.call(19, &string(session.path("real"))).status(), BAD_MESSAGE, "readlink on a file");
    assert_eq!(session.call(19, &string(session.path("nope"))).status(), NO_SUCH_FILE);

    let dangling = session.path("dangling");
    assert_eq!(session.status_of(20, &[string("/does/not/exist"), string(&dangling)].concat()), OK);
    assert_eq!(session.call(19, &string(&dangling)).name(), "/does/not/exist");
    assert_eq!(session.call(7, &string(&dangling)).attrs().permissions.unwrap() & 0o170_000, 0o120_000);
    assert_eq!(session.call(17, &string(&dangling)).status(), NO_SUCH_FILE);

    let hard = session.path("hard");
    let reply = session.extended("hardlink@openssh.com", &[string(session.path("real")), string(&hard)].concat());
    assert_eq!(reply.status(), OK);
    assert_eq!(fs::metadata(session.home().join("hard")).unwrap().nlink(), 2);
    let reply = session.extended("hardlink@openssh.com", &[string(session.path("real")), string(&hard)].concat());
    assert_eq!(reply.status(), FAILURE);
}

#[test]
fn paths_resolve_against_the_home_directory_and_are_not_confined() {
    let mut session = Session::new();
    let home = session.home();
    fs::create_dir(home.join("sub")).unwrap();
    symlink("sub", home.join("alias")).unwrap();

    let real = |session: &mut Session, path: &str| session.call(16, &string(path)).name();
    assert_eq!(real(&mut session, "."), home.display().to_string());
    assert_eq!(real(&mut session, ""), home.display().to_string());
    assert_eq!(real(&mut session, "sub/.."), home.display().to_string());
    assert_eq!(real(&mut session, "alias"), home.join("sub").display().to_string());
    assert_eq!(real(&mut session, "alias/../sub/./new"), home.join("sub/new").display().to_string());
    assert_eq!(real(&mut session, "/"), "/");
    assert_eq!(real(&mut session, "/../.."), "/");
    assert_eq!(real(&mut session, "missing"), home.join("missing").display().to_string());
    assert_eq!(session.call(16, &string("missing/deeper")).status(), NO_SUCH_FILE);
    assert_eq!(session.call(16, &string("missing/..")).status(), NO_SUCH_FILE);

    symlink("loop", home.join("loop")).unwrap();
    assert_eq!(session.call(16, &string("loop/x")).status(), NO_SUCH_FILE);

    session.put("sub/inside", b"in");
    let handle = session.call(3, &[string("sub/inside"), u32s(READ), no_attrs()].concat()).handle();
    assert_eq!(session.read(&handle, 0, 10).data(), b"in");
    let outside = session.call(17, &string("/")).attrs();
    assert_eq!(outside.permissions.unwrap() & 0o170_000, 0o040_000, "absolute paths are not confined to the home");
    let up = session.call(17, &string("../")).attrs();
    assert_eq!(up.permissions.unwrap() & 0o170_000, 0o040_000);

    let expand = |session: &mut Session, path: &str| {
        session.extended("expand-path@openssh.com", &string(path)).name()
    };
    let home = home.display().to_string();
    assert_eq!(expand(&mut session, "~"), home);
    assert_eq!(expand(&mut session, "/~"), home);
    assert_eq!(expand(&mut session, "~/x/y"), format!("{home}/x/y"));
    assert_eq!(expand(&mut session, "/~/x"), format!("{home}/x"));
    assert_eq!(expand(&mut session, "plain/rel"), "plain/rel");
    assert_eq!(expand(&mut session, "/abs"), "/abs");
    assert_eq!(expand(&mut session, "~other/x"), "~other/x");
}

#[test]
fn the_home_directory_falls_back_to_the_root_directory() {
    let engine = Engine::new(Path::new("/definitely/not/a/directory"), owner()).unwrap();
    let mut session = Session { dir: TempDir::new().unwrap(), core: Core::new(engine), next: 1 };
    assert_eq!(session.exchange(&packet(1, &u32s(3))).remove(0).kind, 2);
    assert_eq!(session.call(16, &string(".")).name(), "/");
    assert_eq!(session.call(16, &string("etc/..")).name(), "/");
}

#[test]
fn filesystem_and_limit_extensions_answer() {
    let mut session = Session::new();
    let reply = session.extended("statvfs@openssh.com", &string(session.path(""))).clone_body();
    assert_eq!(reply.0, 201);
    let mut cursor = Cursor(&reply.1);
    let values: Vec<u64> = (0..11).map(|_| cursor.u64()).collect();
    assert!(values[0] > 0 && values[1] > 0 && values[2] > 0, "{values:?}");
    assert!(values[10] >= 100, "name maximum {values:?}");
    assert!(cursor.0.is_empty());

    session.put("f", b"x");
    let handle = session.open("f", READ | WRITE);
    let reply = session.extended("fstatvfs@openssh.com", &string(&handle));
    assert_eq!(reply.kind, 201);
    assert_eq!(reply.body.len(), 88);
    assert_eq!(session.extended("fsync@openssh.com", &string(&handle)).status(), OK);
    session.close(&handle);
    assert_eq!(session.extended("fsync@openssh.com", &string(&handle)).status(), FAILURE);
    assert_eq!(session.extended("statvfs@openssh.com", &string(session.path("missing"))).status(), NO_SUCH_FILE);

    let limits = session.extended("limits@openssh.com", &[]);
    assert_eq!(limits.kind, 201);
    let mut cursor = limits.cursor();
    let (packet_length, read, write, handles) = (cursor.u64(), cursor.u64(), cursor.u64(), cursor.u64());
    assert_eq!(packet_length as usize, MAX_PACKET);
    assert_eq!((read as usize, write as usize), (MAX_DATA, MAX_DATA));
    assert!(read + 64 <= packet_length, "a full read reply must fit the packet limit");
    assert_eq!(handles as usize, MAX_HANDLES);
}

impl Response {
    fn clone_body(&self) -> (u8, Vec<u8>) {
        (self.kind, self.body.clone())
    }
}

#[test]
fn unknown_requests_and_extensions_are_unsupported_not_fatal() {
    let mut session = Session::new();
    assert_eq!(session.call(99, &[]).status(), OP_UNSUPPORTED);
    assert_eq!(session.call(150, b"junk").status(), OP_UNSUPPORTED);
    assert_eq!(session.extended("nope@example.org", &[]).status(), OP_UNSUPPORTED);
    assert_eq!(session.call(5, &[string("short"), u64s(0), u32s(1)].concat()).status(), FAILURE, "a foreign handle");
    session.put("alive", b"");
}

#[cfg(target_os = "linux")]
#[test]
fn files_on_procfs_are_never_opened() {
    let mut session = Session::new();
    for path in [
        "/proc/self/mem",
        "/proc/self/maps",
        "/proc/self/environ",
        "/proc/thread-self/mem",
        "/proc/cpuinfo",
        "/dev/fd/0/../../proc/self/mem",
    ] {
        for flags in [READ, WRITE, READ | WRITE] {
            let reply = session.call(3, &[string(path), u32s(flags), no_attrs()].concat());
            assert_ne!(reply.kind, 102, "{path} was opened with {flags}");
        }
    }
    let pid = std::process::id();
    let reply = session.call(3, &[string(format!("/proc/{pid}/mem")), u32s(READ), no_attrs()].concat());
    assert_eq!(reply.status(), PERMISSION_DENIED);
    symlink("/proc/self/mem", session.home().join("mem-link")).unwrap();
    let reply = session.call(3, &[string("mem-link"), u32s(READ), no_attrs()].concat());
    assert_eq!(reply.status(), PERMISSION_DENIED);
    let reply = session.call(9, &[string("/proc/self/mem"), attrs(&Attrs { size: Some(0), ..Attrs::default() })].concat());
    assert_ne!(reply.status(), OK);
    assert_eq!(session.call(17, &string("/proc/self/maps")).kind, 105, "stat is harmless");
}

#[test]
fn the_number_of_open_handles_is_bounded() {
    let mut session = Session::new();
    session.put("f", b"");
    let handles: Vec<Vec<u8>> = (0..MAX_HANDLES).map(|_| session.open("f", READ)).collect();
    let extra = session.call(3, &[string(session.path("f")), u32s(READ), no_attrs()].concat());
    assert_eq!(extra.status(), FAILURE);
    let dir = session.call(11, &string(session.path("")));
    assert_eq!(dir.status(), FAILURE);
    session.close(&handles[0]);
    let again = session.open("f", READ);
    assert!(!handles.contains(&again), "handles must not be reused straight away");
}

#[cfg(target_os = "linux")]
#[test]
fn opening_a_fifo_cannot_block_the_session() {
    let mut session = Session::new();
    let path = session.home().join("fifo");
    rustix::fs::mknodat(rustix::fs::CWD, &path, rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0)
        .unwrap();
    let handle = session.open("fifo", READ);
    assert_eq!(session.read(&handle, 0, 10).status(), FAILURE, "a read with no writer");
    session.close(&handle);
    let reply = session.call(3, &[string(session.path("fifo")), u32s(WRITE), no_attrs()].concat());
    if reply.kind == 102 {
        session.close(&reply.handle());
    }
}

#[test]
fn errno_values_map_to_status_codes_like_openssh() {
    use rustix::io::Errno;
    for (errno, status) in [
        (Errno::NOENT, 2),
        (Errno::NOTDIR, 2),
        (Errno::BADF, 2),
        (Errno::LOOP, 2),
        (Errno::PERM, 3),
        (Errno::ACCESS, 3),
        (Errno::NAMETOOLONG, 5),
        (Errno::INVAL, 5),
        (Errno::NOSYS, 8),
        (Errno::EXIST, 4),
        (Errno::NOSPC, 4),
        (Errno::ROFS, 4),
        (Errno::ISDIR, 4),
        (Errno::NOTEMPTY, 4),
        (Errno::IO, 4),
    ] {
        assert_eq!(Status::from(errno), Status(status), "{errno}");
    }
    assert_eq!(Status::from(std::io::Error::other("custom")), Status::FAILURE);
}

#[test]
fn long_names_look_like_ls_output() {
    let owner = Owner { uid: 1000, name: "alice".into() };
    let file = Attrs {
        size: Some(1234),
        owner: Some((1000, 100)),
        permissions: Some(0o100_644),
        times: Some((0, 951_782_400)),
    };
    // 2000-02-29 00:00:00 UTC, long before "now"
    let line = String::from_utf8(long_name(&file, b"a b", 1_800_000_000, &owner)).unwrap();
    assert_eq!(line, "-rw-r--r--   1 alice    100          1234 Feb 29  2000 a b");

    let recent = Attrs { times: Some((0, 1_800_000_000 - 3600)), ..file.clone() };
    let line = String::from_utf8(long_name(&recent, b"x", 1_800_000_000, &owner)).unwrap();
    assert!(line.contains(" Jan 15 07:00 "), "{line}");

    let special = Attrs { permissions: Some(0o104_755), owner: Some((7, 8)), ..file.clone() };
    let line = String::from_utf8(long_name(&special, b"s", 1_800_000_000, &owner)).unwrap();
    assert!(line.starts_with("-rwsr-xr-x   1 7        8 "), "{line}");
    let sticky = Attrs { permissions: Some(0o041_777), ..file.clone() };
    let line = String::from_utf8(long_name(&sticky, b"t", 1_800_000_000, &owner)).unwrap();
    assert!(line.starts_with("drwxrwxrwt"), "{line}");
    let setgid = Attrs { permissions: Some(0o102_640), ..file };
    let line = String::from_utf8(long_name(&setgid, b"g", 1_800_000_000, &owner)).unwrap();
    assert!(line.starts_with("-rw-r-S---"), "{line}");
}
