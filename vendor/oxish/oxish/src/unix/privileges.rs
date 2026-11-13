use std::io;

use crate::login::UserEntry;

/// Become the account: supplementary groups, then group, then user, and prove it took
///
/// Linux credentials are per thread, so this must run while the process has a single thread
/// (before any runtime exists). A root process sets all three of each ID, then checks the real,
/// effective and group lists and that root cannot be regained. A process that is not root cannot
/// change identity: it is accepted only when it already is the account.
pub(crate) fn drop_to(user: &UserEntry, allow_root: bool) -> io::Result<()> {
    user.check(allow_root).map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
    // Non-dumpable before the credentials change, and again after: the kernel resets the flag to
    // `fs.suid_dumpable` when the effective IDs change, which is 1 (dumpable) on some systems. The
    // host key only arrives after both, so no copy of it is ever in a dumpable process.
    seal()?;
    switch(user)?;
    seal()?;
    let _ = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    Ok(())
}

/// Mark the process non-dumpable (no `ptrace`, no `/proc/PID/mem`) and prove it
#[cfg(target_os = "linux")]
fn seal() -> io::Result<()> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};

    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    match dumpable_behavior()? {
        DumpableBehavior::NotDumpable => Ok(()),
        _ => Err(denied("the process could not be made non-dumpable".to_owned())),
    }
}

#[cfg(not(target_os = "linux"))]
fn seal() -> io::Result<()> {
    Ok(())
}

fn denied(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn is_account(user: &UserEntry) -> bool {
    use rustix::process::{getegid, geteuid, getgid, getuid};

    [getuid(), geteuid()].iter().all(|id| id.as_raw() == user.uid)
        && [getgid(), getegid()].iter().all(|id| id.as_raw() == user.gid)
}

#[cfg(target_os = "linux")]
fn switch(user: &UserEntry) -> io::Result<()> {
    use rustix::{
        process::{Gid, Uid, getgroups},
        thread::{set_thread_gid, set_thread_groups, set_thread_res_gid, set_thread_res_uid, set_thread_uid},
    };

    if rustix::process::geteuid().as_raw() != 0 {
        return match is_account(user) {
            true => Ok(()),
            false => Err(denied(format!(
                "cannot serve account {}: the server is not root and is not that account",
                user.name
            ))),
        };
    }

    let (uid, gid) = (Uid::from_raw(user.uid), Gid::from_raw(user.gid));
    let groups: Vec<Gid> = user.groups.iter().copied().map(Gid::from_raw).collect();
    set_thread_groups(&groups)?;
    set_thread_res_gid(gid, gid, gid)?;
    set_thread_res_uid(uid, uid, uid)?;

    if !is_account(user) {
        return Err(denied(format!("dropping to account {} did not take effect", user.name)));
    }
    let mut held: Vec<u32> = getgroups()?.iter().map(|group| group.as_raw()).collect();
    let mut wanted = user.groups.clone();
    held.sort_unstable();
    held.dedup();
    wanted.sort_unstable();
    wanted.dedup();
    if held != wanted {
        return Err(denied(format!("supplementary groups of {} are {held:?}, not {wanted:?}", user.name)));
    }
    // Root can be regained only if an ID the account does not hold can be taken. Probe with an ID
    // other than the account's own: an account in group 0 (allowed with `--allow-root-login`)
    // may of course become group 0, and that proves nothing. A uid 0 account is root already.
    if user.uid != 0 {
        let other_gid = Gid::from_raw(if user.gid == 0 { 1 } else { 0 });
        if set_thread_uid(Uid::ROOT).is_ok() || set_thread_gid(other_gid).is_ok() {
            return Err(denied(format!("root can be regained after dropping to {}", user.name)));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn switch(user: &UserEntry) -> io::Result<()> {
    match is_account(user) {
        true => Ok(()),
        false => Err(denied(format!(
            "cannot serve account {}: switching users is only supported on Linux",
            user.name
        ))),
    }
}
