mod support;

use std::time::Duration;

use support::*;
use oxish_client::{ExecOptions, StreamOptions};

fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fd directory").count()
}

#[test]
fn connections_that_fail_or_close_release_their_descriptors() {
    let before = open_descriptors();
    for round in 0..8 {
        let peer = spawn(Behavior::default(), move |link| {
            link.accept_authentication();
            let opened = link.accept_exec(1 << 20, 32 * 1024);
            if round % 2 == 0 {
                link.disconnect();
            } else {
                link.exit_status(opened.client_channel, 0);
                link.eof(opened.client_channel);
                link.close(opened.client_channel);
                link.expect_close();
            }
        });
        let mut connection = peer.connect(Duration::from_secs(5));
        let _ = connection.exec("command", &ExecOptions::default());
        if round % 2 == 0 {
            assert!(!connection.is_usable());
            let _ = connection.exec_stream(
                "again",
                &StreamOptions::default(),
                None,
                &mut std::io::sink(),
                &mut std::io::sink(),
            );
        }
        drop(connection);
        peer.finish();
    }
    assert_eq!(open_descriptors(), before);
}
