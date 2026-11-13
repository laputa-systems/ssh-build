#![forbid(unsafe_code)]

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use anyhow::Context as _;
use oxish::{DEFAULT_PROVIDER, GitPolicy, LoginSession, drop_privileges, launch, require_supported_cpu, resume, resume_login};

enum Serve {
    Git(GitPolicy),
    Login(LoginSession),
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if let [verb, program, argv0, rest @ ..] = args.as_slice() {
        if verb == "launch" {
            let error = launch(program, argv0, rest);
            eprintln!("oxish-session: cannot execute {}: {error}", program.to_string_lossy());
            return ExitCode::from(127);
        }
    }

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oxish-session: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<OsString>) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    let serve = match args.as_slice() {
        [repo_root, git_dir] => Serve::Git(
            GitPolicy::new(&PathBuf::from(repo_root), &PathBuf::from(git_dir)).context("invalid git policy")?,
        ),
        [login, rest @ ..] if login == "login" => {
            let login = LoginSession::from_args(rest.iter().cloned()).context("invalid login arguments")?;
            // Credentials are per thread on Linux: become the account before the runtime has any other thread.
            drop_privileges(&login).context("cannot become the account")?;
            Serve::Login(login)
        }
        _ => anyhow::bail!("usage: oxish-session <repository-root> <git-directory> | login <options> | launch <program> <argv0> [args]"),
    };

    require_supported_cpu()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let session = match serve {
                Serve::Git(policy) => resume(DEFAULT_PROVIDER, policy)?,
                Serve::Login(login) => resume_login(DEFAULT_PROVIDER, login)?,
            };
            Ok(session.run().await?)
        })
}
