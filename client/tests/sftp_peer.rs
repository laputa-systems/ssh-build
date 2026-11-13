mod support;

use std::time::Duration;

use oxish_client::Error;
use oxish_client::sftp::{Sftp, SftpError};
use support::*;

const TIMEOUT: Duration = Duration::from_secs(5);

fn subsystem(link: &mut Link) -> u32 {
    link.accept_authentication();
    let open = link.expect(CHANNEL_OPEN);
    let kind_length = open.u32_at(0) as usize;
    let client_channel = open.u32_at(4 + kind_length);
    link.send(&message(
        CHANNEL_CONFIRMATION,
        &[&number(client_channel), &number(SERVER_CHANNEL), &number(1 << 20), &number(32 * 1024)],
    ));
    let request = link.expect(CHANNEL_REQUEST);
    assert_eq!(request.string_at(4), b"subsystem");
    assert_eq!(request.string_at(18), b"sftp");
    client_channel
}

fn sftp_frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    packet.push(kind);
    packet.extend_from_slice(body);
    packet
}

#[test]
fn a_refused_subsystem_is_reported_as_rejected() {
    let peer = spawn(Behavior::default(), |link| {
        let channel = subsystem(link);
        link.send(&message(CHANNEL_FAILURE, &[&number(channel)]));
    });
    let result = Sftp::connect(peer.connect(TIMEOUT), None);
    assert!(
        matches!(result, Err(SftpError::Transport(Error::Rejected { request: "subsystem" }))),
        "{:?}",
        result.err()
    );
    peer.finish();
}

fn serve_garbage(reply: Vec<u8>) -> Result<(), SftpError> {
    let peer = spawn(Behavior::default(), move |link| {
        let channel = subsystem(link);
        link.send(&message(CHANNEL_SUCCESS, &[&number(channel)]));
        let init = link.expect(CHANNEL_DATA);
        assert_eq!(init.string_at(4), [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        for piece in reply.chunks(3) {
            link.data(channel, piece);
        }
    });
    let result = Sftp::connect(peer.connect(TIMEOUT), None).map(|_| ());
    peer.finish();
    result
}

#[test]
fn a_well_formed_version_reply_is_accepted_in_small_pieces() {
    let mut body = 3u32.to_be_bytes().to_vec();
    for text in [&b"posix-rename@openssh.com"[..], b"1"] {
        body.extend((text.len() as u32).to_be_bytes());
        body.extend(text);
    }
    assert!(serve_garbage(sftp_frame(2, &body)).is_ok());
}

#[test]
fn malformed_server_data_is_an_error_not_a_panic() {
    for reply in [
        vec![0xff; 4],
        sftp_frame(2, &[0, 0, 0]),
        sftp_frame(2, &2u32.to_be_bytes()),
        sftp_frame(101, &[0, 0, 0, 0, 0, 0, 0, 0]),
        sftp_frame(2, &[&3u32.to_be_bytes()[..], &[0, 0, 0, 9, 1]].concat()),
        vec![0, 0, 0, 0],
    ] {
        match serve_garbage(reply.clone()) {
            Err(SftpError::Protocol(_) | SftpError::Unsupported(_) | SftpError::Transport(_)) => {}
            other => panic!("{reply:?} gave {other:?}"),
        }
    }
}

#[test]
fn a_server_that_hangs_up_mid_session_is_a_transport_error() {
    let peer = spawn(Behavior::default(), |link| {
        let channel = subsystem(link);
        link.send(&message(CHANNEL_SUCCESS, &[&number(channel)]));
        link.expect(CHANNEL_DATA);
        link.send(&message(CHANNEL_EOF, &[&number(channel)]));
        link.send(&message(CHANNEL_CLOSE, &[&number(channel)]));
    });
    let result = Sftp::connect(peer.connect(TIMEOUT), None);
    assert!(matches!(result, Err(SftpError::Transport(_))), "{:?}", result.err());
    peer.finish();
}
