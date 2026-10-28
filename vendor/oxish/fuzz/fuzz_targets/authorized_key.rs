#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::auth::AuthorizedKey;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = core::str::from_utf8(data) else {
        return;
    };

    if let Some(key) = AuthorizedKey::from_str(line, provider::DEFAULT_PROVIDER) {
        let _ = key.options.git_access;
        assert!(key.same_key(&key));
    }
});
