use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use data_encoding::BASE64;
use oxish_client::oxish_proto::OpenSshKeyV1;

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static RAW: Cell<[u8; 24]> = const { Cell::new([0; 24]) };
    static ENCODED: Cell<[u8; 24]> = const { Cell::new([0; 24]) };
    static UNWIPED: Cell<usize> = const { Cell::new(0) };
}

struct WatchFrees;

fn inspect(block: *mut u8, length: usize) {
    if length < 24 || !WATCHING.with(Cell::get) {
        return;
    }
    // SAFETY: the allocator supplies a live block of `length` bytes before releasing it.
    let bytes = unsafe { std::slice::from_raw_parts(block, length) };
    let raw = RAW.with(Cell::get);
    let encoded = ENCODED.with(Cell::get);
    if bytes.windows(24).any(|window| window == raw || window == encoded) {
        UNWIPED.with(|count| count.set(count.get() + 1));
    }
}

// SAFETY: allocation operations forward the caller's pointer, layout and requested size unchanged.
unsafe impl GlobalAlloc for WatchFrees {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        inspect(block, layout.size());
        // SAFETY: forwarded before any other owner can reuse the allocation.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        inspect(block, layout.size());
        // SAFETY: forwarded with the caller's valid allocation and new size.
        unsafe { System.realloc(block, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchFrees = WatchFrees;

fn watched(run: impl FnOnce()) -> usize {
    UNWIPED.with(|count| count.set(0));
    WATCHING.with(|watching| watching.set(true));
    run();
    WATCHING.with(|watching| watching.set(false));
    UNWIPED.with(Cell::get)
}

#[test]
fn private_key_loading_wipes_freed_and_reallocated_buffers_on_success_and_errors() {
    let directory = tempfile::tempdir().expect("private fixture directory");
    let path = directory.path().join("key");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "wipe-regression", "-f"])
        .arg(&path).status().expect("fixture key generation");
    assert!(status.success());
    let original = std::fs::read_to_string(&path).expect("fixture key");
    let compact: String = original.lines().skip(1).take_while(|line| !line.starts_with("-----")).collect();
    let parsed: OpenSshKeyV1 = original.parse().expect("fixture parser");
    let pkcs8 = parsed.pkcs8_keys().next().expect("fixture key material");
    RAW.with(|raw| raw.set(pkcs8[pkcs8.len() - 32..pkcs8.len() - 8].try_into().expect("seed marker")));
    ENCODED.with(|encoded| encoded.set(compact.as_bytes()[216..240].try_into().expect("encoded seed marker")));
    drop(parsed);
    drop(pkcs8);
    let decoded = BASE64.decode(compact.as_bytes()).expect("fixture encoding");
    let mut invalid_encoding = compact.clone().into_bytes();
    let last = invalid_encoding.len() - 5;
    invalid_encoding[last] = b'!';
    let invalid_encoding = String::from_utf8(invalid_encoding).expect("ascii fixture");
    let mut encrypted = decoded.clone();
    encrypted[19..23].copy_from_slice(b"evil");
    let mut bad_padding = decoded;
    *bad_padding.last_mut().expect("padding") = 0;
    let pem = |body: &str| format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n");
    let cases = [
        (original.clone(), true),
        (pem(&invalid_encoding), false),
        (original.replace("-----END OPENSSH PRIVATE KEY-----", ""), false),
        (pem(&BASE64.encode(&encrypted)), false),
        (pem(&BASE64.encode(&bad_padding)), false),
    ];
    for (text, valid) in cases {
        std::fs::write(&path, &text).expect("fixture mutation");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("private mode");
        let mut loaded = false;
        let count = watched(|| {
            let result = oxish_client::auth::load_key(&path, oxish_client::DEFAULT_PROVIDER);
            loaded = result.is_ok();
            drop(result);
        });
        assert_eq!(loaded, valid, "private-key loader outcome");
        assert_eq!(count, 0, "loader freed or reallocated private-key material without wiping it");
        let count = watched(|| {
            let result = text.parse::<OpenSshKeyV1>();
            loaded = result.is_ok();
            drop(result);
        });
        assert_eq!(loaded, valid, "private-key parser outcome");
        assert_eq!(count, 0, "parser freed or reallocated private-key material without wiping it");
    }
}
