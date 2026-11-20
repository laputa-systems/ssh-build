use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use graviola::hashing::{Hash, HashContext, Sha256, Sha512};
use oxish_proto::named::KeyExchangeAlgorithm;

const SECRET: &[u8] = b"xsh-shared-secret-wipe-sentinel";

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
}

static UNWIPED: AtomicUsize = AtomicUsize::new(0);

struct WatchFrees;

// SAFETY: Allocations are forwarded to the system allocator, and deallocation inspects the live block before forwarding it.
unsafe impl GlobalAlloc for WatchFrees {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if layout.size() >= SECRET.len() && WATCHING.with(Cell::get) {
            let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
            if bytes.windows(SECRET.len()).any(|window| window == SECRET) {
                UNWIPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchFrees = WatchFrees;

#[test]
fn sha_contexts_wipe_buffered_secrets_on_drop() {
    let mut sha256 = Box::new(Sha256::new());
    let mut sha512 = Box::new(Sha512::new());
    sha256.update(SECRET);
    sha512.update(SECRET);
    WATCHING.with(|watching| watching.set(true));
    drop(sha256);
    drop(sha512);
    WATCHING.with(|watching| watching.set(false));
    assert_eq!(UNWIPED.load(Ordering::Relaxed), 0, "freed hash contexts held the shared secret");
}

fn unwiped_after(run: impl FnOnce()) -> usize {
    let before = UNWIPED.load(Ordering::Relaxed);
    WATCHING.with(|watching| watching.set(true));
    run();
    WATCHING.with(|watching| watching.set(false));
    UNWIPED.load(Ordering::Relaxed) - before
}

#[test]
fn provider_hash_contexts_wipe_buffered_secrets_when_finished_or_forked() {
    let hash = oxish_graviola::DEFAULT_PROVIDER
        .hash(&KeyExchangeAlgorithm::MlKem768X25519Sha256)
        .expect("SHA-256 for the hybrid exchange");
    let finished = unwiped_after(|| {
        let mut context = hash.start();
        context.update(SECRET);
        drop(context.finish());
    });
    let forked = unwiped_after(|| {
        let mut context = hash.start();
        context.update(SECRET);
        let fork = context.fork();
        drop(fork.finish());
        drop(context.finish());
    });
    assert_eq!((finished, forked), (0, 0), "finished hash contexts freed the shared secret unwiped");
}
