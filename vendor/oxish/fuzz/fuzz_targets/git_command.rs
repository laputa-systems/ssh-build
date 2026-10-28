#![no_main]

use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use libfuzzer_sys::fuzz_target;
use oxish::{GitAccess, GitPolicy};

struct Fixture {
    policy: GitPolicy,
    root: PathBuf,
    bin: PathBuf,
}

fn dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let base = std::env::temp_dir().join(format!("oxish-fuzz-git-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        dir(&base);
        let base = fs::canonicalize(&base).unwrap();
        let (root, bin) = (base.join("repos"), base.join("bin"));
        dir(&root);
        dir(&bin);
        fs::write(bin.join("git"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("git", bin.join("git-upload-pack")).unwrap();
        symlink("git", bin.join("git-receive-pack")).unwrap();
        for name in ["a.git", "team/b.git"] {
            let repo = root.join(name);
            dir(&repo.join("objects"));
            dir(&repo.join("refs"));
            fs::write(repo.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        }
        symlink(&base, root.join("up")).unwrap();
        let policy = GitPolicy::new(&root, &bin).unwrap();
        Fixture { policy, root, bin }
    })
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    for access in [Some(GitAccess::Read), Some(GitAccess::Write), None] {
        let Ok(command) = fixture.policy.authorize(data, access) else {
            continue;
        };

        // Whatever the input, the program is one of ours and the repository is under the root.
        assert!(command.program.starts_with(&fixture.bin));
        let repository = Path::new(command.args.last().unwrap());
        assert!(repository.starts_with(&fixture.root));
        assert!(!repository.components().any(|c| c.as_os_str() == ".."));
        assert!(command.args.iter().all(|arg| arg.to_str().is_some()));
        assert!(access.is_some());
    }
});
