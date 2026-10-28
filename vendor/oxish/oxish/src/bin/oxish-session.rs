use std::{env, path::PathBuf};

use anyhow::Context as _;
use oxish::{DEFAULT_PROVIDER, GitPolicy, resume};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    let mut args = env::args_os().skip(1);
    let (Some(repo_root), Some(git_dir), None) = (args.next(), args.next(), args.next()) else {
        anyhow::bail!("usage: oxish-session <repository-root> <git-directory>");
    };

    let policy = GitPolicy::new(&PathBuf::from(repo_root), &PathBuf::from(git_dir))
        .context("invalid git policy")?;
    Ok(resume(DEFAULT_PROVIDER, policy)?.run().await?)
}
