mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use support::*;
use oxish_client::{ExecOptions, ExecStatus};

const SENTINEL: &[u8; 32] = b"xsh-stdin-sentinel-0123456789abc";

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
}

static UNWIPED: AtomicUsize = AtomicUsize::new(0);

struct WatchFrees;

// SAFETY: every call is forwarded unchanged to the system allocator; `dealloc` only reads the
// block it is handed, which is still allocated and `layout.size()` bytes long.
unsafe impl GlobalAlloc for WatchFrees {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if layout.size() >= SENTINEL.len() && WATCHING.with(Cell::get) {
            // SAFETY: `block` is a live allocation of `layout.size()` bytes until the call below.
            let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
            if bytes.windows(SENTINEL.len()).any(|window| window == SENTINEL) {
                UNWIPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: forwarded with the block and layout the caller allocated it with.
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchFrees = WatchFrees;

#[test]
fn stdin_bytes_are_wiped_before_the_client_frees_them() {
    let peer = spawn(Behavior::default(), |link| {
        link.accept_authentication();
        let opened = link.accept_exec(1 << 20, 32 * 1024);
        loop {
            let frame = link.recv();
            if frame.kind == CHANNEL_EOF {
                break;
            }
        }
        link.exit_status(opened.client_channel, 0);
        link.eof(opened.client_channel);
        link.close(opened.client_channel);
        link.expect_close();
    });
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("stdin");
    let mut file = std::fs::File::create(&path).expect("stdin file");
    for _ in 0..4096 {
        file.write_all(SENTINEL).expect("write stdin file");
    }
    drop(file);
    let mut connection = peer.connect(Duration::from_secs(5));
    let options = ExecOptions {
        stdin: Some(SENTINEL.repeat(4096)),
        stdin_file: Some(std::fs::File::open(&path).expect("open stdin file")),
        ..ExecOptions::default()
    };
    WATCHING.with(|watching| watching.set(true));
    let result = connection.exec("cat >/dev/null", &options);
    WATCHING.with(|watching| watching.set(false));
    assert_eq!(result.expect("exec").status, ExecStatus::Exited(0));
    assert_eq!(UNWIPED.load(Ordering::Relaxed), 0, "freed blocks still held stdin bytes");
    drop(options);
    drop(connection);
    peer.finish();
}
