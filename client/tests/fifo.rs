use std::time::Duration;

use oxish_client::exec::{create_output_file, open_stdin_file};

fn fifo(directory: &tempfile::TempDir) -> std::path::PathBuf {
    let path = directory.path().join("fifo");
    let status = std::process::Command::new("mkfifo").arg(&path).status().expect("mkfifo");
    assert!(status.success());
    path
}

fn within_a_second<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("the open returns instead of waiting for the other end of the FIFO")
}

#[test]
fn a_fifo_given_as_input_opens_without_a_writer() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fifo(&directory);
    within_a_second(move || open_stdin_file(&path)).expect("opens");
}

#[test]
fn a_fifo_given_as_output_without_a_reader_is_refused_at_once() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fifo(&directory);
    within_a_second(move || create_output_file(&path)).expect_err("no reader");
}

#[test]
fn a_fifo_given_as_output_with_a_reader_opens_blocking() {
    use std::os::fd::AsFd;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fifo(&directory);
    let _reader = open_stdin_file(&path).expect("reader");
    let file = within_a_second(move || create_output_file(&path)).expect("opens");
    let flags = rustix::fs::fcntl_getfl(file.as_fd()).expect("flags");
    assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
}
