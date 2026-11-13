use std::io::stdout;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxish_client::cli::{Connect, ConnectArgs, RemoteSpec, default_user, open_sftp, parse_remote};
use oxish_client::copy::{CopyError, CopyOptions, download, upload};
use oxish_client::progress::Meter;
use oxish_client::sftp::Sftp;

const USAGE: &str = "usage: oxish-scp [-r] [-p] [-P PORT] [-i KEY | --agent SOCKET --agent-identity SHA256:...]
                 (--host-key SHA256:... | --known-hosts PATH) SOURCE... DEST
       a path is local, or [user@]host:path for the one remote side";

const EXIT_FAILURE: u8 = 1;

struct Options {
    connect: Connect,
    copy: CopyOptions,
    paths: Vec<String>,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut connect = ConnectArgs::new("-P");
    let mut copy = CopyOptions::default();
    let mut paths = Vec::new();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--" => {
                paths.extend(args.by_ref());
                break;
            }
            "-h" | "--help" => return Err(String::new()),
            other if connect.accept(other, &mut args)? => {}
            other if other.len() > 1
                && other.starts_with('-')
                && other[1..].bytes().all(|letter| matches!(letter, b'r' | b'p')) =>
            {
                for letter in other[1..].bytes() {
                    if letter == b'r' {
                        copy.recursive = true;
                    } else {
                        copy.preserve = true;
                    }
                }
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"));
            }
            _ => paths.push(argument),
        }
    }
    if paths.len() < 2 {
        return Err("need at least one source and a destination".to_owned());
    }
    Ok(Options {
        connect: connect.finish()?,
        copy,
        paths,
    })
}

enum Plan {
    Download {
        remote: RemoteSpec,
        sources: Vec<String>,
        destination: PathBuf,
    },
    Upload {
        remote: RemoteSpec,
        sources: Vec<PathBuf>,
        destination: String,
    },
}

fn same_host(left: &RemoteSpec, right: &RemoteSpec) -> bool {
    left.user == right.user && left.host == right.host
}

fn plan(paths: &[String]) -> Result<Plan, String> {
    let (destination, sources) = paths.split_last().ok_or("need a destination")?;
    let remote_destination = parse_remote(destination);
    let remote_sources: Vec<Option<RemoteSpec>> = sources.iter().map(|path| parse_remote(path)).collect();
    match remote_destination {
        Some(remote) => {
            if remote_sources.iter().any(Option::is_some) {
                return Err("copying between two remote hosts is not supported".to_owned());
            }
            Ok(Plan::Upload {
                destination: remote.path.clone(),
                remote,
                sources: sources.iter().map(PathBuf::from).collect(),
            })
        }
        None => {
            let mut specs = remote_sources.into_iter();
            let first = specs
                .next()
                .flatten()
                .ok_or("one side must be remote: [user@]host:path")?;
            let mut paths = vec![first.path.clone()];
            for spec in specs {
                let spec = spec.ok_or("a local source cannot be mixed with remote sources")?;
                if !same_host(&first, &spec) {
                    return Err("all remote sources must name the same user and host".to_owned());
                }
                paths.push(spec.path);
            }
            Ok(Plan::Download {
                remote: first,
                sources: paths,
                destination: PathBuf::from(destination),
            })
        }
    }
}

fn remote_path(path: &str) -> Vec<u8> {
    match path {
        "" | "~" => b".".to_vec(),
        _ => path.strip_prefix("~/").unwrap_or(path).as_bytes().to_vec(),
    }
}

fn report(error: &CopyError) {
    eprintln!("oxish-scp: {error}");
}

enum Failure {
    Usage(String),
    Run(String),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Run(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::Run(message.to_owned())
    }
}

fn run() -> Result<(), Failure> {
    let options = parse(std::env::args().skip(1)).map_err(Failure::Usage)?;
    let plan = plan(&options.paths).map_err(Failure::Usage)?;
    let remote = match &plan {
        Plan::Download { remote, .. } | Plan::Upload { remote, .. } => remote,
    };
    let user = remote
        .user
        .clone()
        .or_else(default_user)
        .ok_or("no user in the remote path and USER is unset")?;
    let mut sftp = open_sftp(&options.connect, &remote.host, &user)?;
    let mut meter = Meter::new(stdout());
    let mut failed = false;
    let mut fatal = false;
    match plan {
        Plan::Download {
            sources,
            destination,
            ..
        } => {
            if sources.len() > 1 && !destination.is_dir() {
                return Err(format!("{}: not a directory", destination.display()).into());
            }
            for source in sources {
                if let Err(error) = download(
                    &mut sftp,
                    &remote_path(&source),
                    &destination,
                    options.copy,
                    &mut meter,
                ) {
                    report(&error);
                    failed = true;
                    if error.is_fatal() {
                        fatal = true;
                        break;
                    }
                }
            }
        }
        Plan::Upload {
            sources,
            destination,
            ..
        } => {
            let target = remote_path(&destination);
            if sources.len() > 1 && !is_remote_dir(&mut sftp, &target) {
                return Err(format!("{destination}: not a directory").into());
            }
            for source in sources {
                if let Err(error) = upload(&mut sftp, Path::new(&source), &target, options.copy, &mut meter) {
                    report(&error);
                    failed = true;
                    if error.is_fatal() {
                        fatal = true;
                        break;
                    }
                }
            }
        }
    }
    if !fatal {
        sftp.disconnect();
    }
    if failed { Err(Failure::Run(String::new())) } else { Ok(()) }
}

fn is_remote_dir(sftp: &mut Sftp, path: &[u8]) -> bool {
    sftp.stat(path).is_ok_and(|attrs| attrs.is_dir())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            match failure {
                Failure::Usage(message) => {
                    if !message.is_empty() {
                        eprintln!("oxish-scp: {message}");
                    }
                    eprintln!("{USAGE}");
                }
                Failure::Run(message) if !message.is_empty() => eprintln!("oxish-scp: {message}"),
                Failure::Run(_) => {}
            }
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(text: &str) -> impl Iterator<Item = String> {
        text.split_whitespace().map(str::to_owned).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn flags_cluster_and_paths_collect() {
        let options = parse(arguments("-rp -P 2222 -i key --host-key SHA256:x a b host:c")).expect("parses");
        assert!(options.copy.recursive && options.copy.preserve);
        assert_eq!(options.connect.port, 2222);
        assert_eq!(options.paths, ["a", "b", "host:c"]);
    }

    #[test]
    fn trust_and_two_paths_are_required() {
        assert!(parse(arguments("-i key a host:b")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x a")).is_err());
        assert!(parse(arguments("-i key --host-key SHA256:x -z a b")).is_err());
    }

    #[test]
    fn the_remote_side_decides_the_direction() {
        let paths = |text: &str| text.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert!(matches!(plan(&paths("a b u@h:dst")), Ok(Plan::Upload { .. })));
        assert!(matches!(plan(&paths("u@h:a u@h:b dst")), Ok(Plan::Download { .. })));
        assert!(plan(&paths("a b")).is_err());
        assert!(plan(&paths("u@h:a v@h:b dst")).is_err());
        assert!(plan(&paths("u@h:a dst2 dst")).is_err());
        assert!(plan(&paths("u@h:a v@h:b")).is_err());
        assert!(plan(&paths("./a:b dst")).is_err());
    }

    #[test]
    fn remote_paths_are_relative_to_the_home_directory() {
        assert_eq!(remote_path(""), b".");
        assert_eq!(remote_path("~"), b".");
        assert_eq!(remote_path("~/x/y"), b"x/y");
        assert_eq!(remote_path("/abs"), b"/abs");
        assert_eq!(remote_path("rel/p"), b"rel/p");
    }
}
