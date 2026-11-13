use std::io::{BufRead, IsTerminal, Write, stdin, stdout};
use std::path::Path;
use std::process::ExitCode;

use oxish_client::cli::{Connect, ConnectArgs, default_user, open_sftp, parse_host_argument, value};
use oxish_client::copy::{CopyOptions, display, download, join_remote, upload};
use oxish_client::progress::{Meter, human};
use oxish_client::sftp::{Attrs, DirEntry, Sftp, SftpError, StatVfs};

const USAGE: &str = "usage: oxish-sftp [-P PORT] [-i KEY | --agent SOCKET --agent-identity SHA256:...]
                  (--host-key SHA256:... | --known-hosts PATH) [-b BATCHFILE] [user@]host[:path]";

const HELP: &str = "Available commands:
ls [-1alh] [path]                  list a remote directory
cd [path]                          change the remote directory
lcd path                           change the local directory
pwd | lpwd                         print the remote | local directory
lmkdir path                        create a local directory
get [-pr] remote [local]           download a file, or a tree with -r
put [-pr] local [remote]           upload a file, or a tree with -r
mkdir path | rmdir path | rm path  create, remove a directory, remove a file
rename old new                     rename, replacing the target where the server allows
ln [-s] target link                make a hard link, or with -s a symbolic link
symlink target link                make a symbolic link
chmod octal-mode path              change permissions
df [-h] [path]                     file system usage
exit | quit | bye                  leave
A leading - on a command in a batch file lets the batch go on after its failure.";

const EXIT_FAILURE: u8 = 1;

struct Options {
    connect: Connect,
    batch: Option<String>,
    user: String,
    host: String,
    path: String,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut connect = ConnectArgs::new("-P");
    let mut batch = None;
    let mut target = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--" => {
                target = args.next();
                break;
            }
            "-h" | "--help" => return Err(String::new()),
            "-b" => batch = Some(value(&mut args, "-b")?),
            other if connect.accept(other, &mut args)? => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"));
            }
            _ => {
                target = Some(argument);
                break;
            }
        }
    }
    if args.next().is_some() {
        return Err("unexpected argument after the target".into());
    }
    let target = target.ok_or_else(|| "missing [user@]host".to_owned())?;
    let spec = parse_host_argument(&target)?;
    let user = spec
        .user
        .or_else(default_user)
        .ok_or_else(|| "no user@ in the target and USER is unset".to_owned())?;
    Ok(Options {
        connect: connect.finish()?,
        batch,
        user,
        host: spec.host,
        path: spec.path,
    })
}

fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' => {
                started = true;
                loop {
                    match characters.next() {
                        Some('\'') => break,
                        Some(inner) => word.push(inner),
                        None => return Err("unterminated single quote".to_owned()),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match characters.next() {
                        Some('"') => break,
                        Some('\\') => match characters.next() {
                            Some(escaped @ ('"' | '\\')) => word.push(escaped),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err("unterminated double quote".to_owned()),
                        },
                        Some(inner) => word.push(inner),
                        None => return Err("unterminated double quote".to_owned()),
                    }
                }
            }
            '\\' => {
                started = true;
                word.push(characters.next().ok_or("trailing backslash")?);
            }
            space if space.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            other => {
                started = true;
                word.push(other);
            }
        }
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

fn flags<'a>(words: &'a [String], allowed: &str) -> Result<(String, &'a [String]), String> {
    let mut letters = String::new();
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if word == "--" {
            index += 1;
            break;
        }
        if word.len() > 1 && word.starts_with('-') {
            for letter in word[1..].chars() {
                if !allowed.contains(letter) {
                    return Err(format!("unsupported flag -{letter}"));
                }
                letters.push(letter);
            }
            index += 1;
        } else {
            break;
        }
    }
    Ok((letters, &words[index..]))
}

fn say(text: &str) {
    let mut out = stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

struct Failure {
    message: String,
    fatal: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            fatal: false,
        }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

fn context<T>(name: &str, path: &[u8], result: Result<T, SftpError>) -> Result<T, Failure> {
    result.map_err(|error| Failure {
        message: format!("{name} {}: {error}", display(path)),
        fatal: error.is_fatal(),
    })
}

enum Flow {
    Continue,
    Exit,
}

struct Shell {
    sftp: Sftp,
    cwd: Vec<u8>,
    home: Vec<u8>,
    meter: Meter,
}

impl Shell {
    fn resolve(&self, path: &str) -> Vec<u8> {
        if path.starts_with('/') {
            path.as_bytes().to_vec()
        } else if path == "~" {
            self.home.clone()
        } else if let Some(rest) = path.strip_prefix("~/") {
            join_remote(&self.home, rest.as_bytes())
        } else {
            join_remote(&self.cwd, path.as_bytes())
        }
    }

    fn run(&mut self, words: &[String]) -> Result<Flow, Failure> {
        let Some((command, rest)) = words.split_first() else {
            return Ok(Flow::Continue);
        };
        self.dispatch(command, rest)
    }

    fn dispatch(&mut self, command: &str, rest: &[String]) -> Result<Flow, Failure> {
        match command {
            "exit" | "quit" | "bye" => return Ok(Flow::Exit),
            "help" | "?" => say(HELP),
            "pwd" => say(&format!("Remote working directory: {}", display(&self.cwd))),
            "lpwd" => {
                let directory = std::env::current_dir().map_err(|error| format!("lpwd: {error}"))?;
                say(&format!("Local working directory: {}", directory.display()));
            }
            "lcd" => {
                let [path] = rest else {
                    return Err("usage: lcd path".into());
                };
                std::env::set_current_dir(path).map_err(|error| format!("lcd {path}: {error}"))?;
            }
            "lmkdir" => {
                let [path] = rest else {
                    return Err("usage: lmkdir path".into());
                };
                std::fs::create_dir(path).map_err(|error| format!("lmkdir {path}: {error}"))?;
            }
            "cd" => self.cd(rest)?,
            "ls" | "dir" => self.ls(rest)?,
            "get" => self.transfer(rest, true)?,
            "put" => self.transfer(rest, false)?,
            "mkdir" => {
                let [path] = rest else {
                    return Err("usage: mkdir path".into());
                };
                let target = self.resolve(path);
                context("mkdir", &target, self.sftp.mkdir(&target, &Attrs::default()))?;
            }
            "rmdir" => {
                let [path] = rest else {
                    return Err("usage: rmdir path".into());
                };
                let target = self.resolve(path);
                context("rmdir", &target, self.sftp.rmdir(&target))?;
            }
            "rm" => {
                let [path] = rest else {
                    return Err("usage: rm path".into());
                };
                let target = self.resolve(path);
                context("rm", &target, self.sftp.remove(&target))?;
            }
            "rename" => {
                let [from, to] = rest else {
                    return Err("usage: rename old new".into());
                };
                let (from, to) = (self.resolve(from), self.resolve(to));
                context("rename", &from, self.sftp.rename(&from, &to))?;
            }
            "ln" | "symlink" => self.link(command, rest)?,
            "chmod" => {
                let [mode, path] = rest else {
                    return Err("usage: chmod octal-mode path".into());
                };
                let mode = u32::from_str_radix(mode, 8)
                    .ok()
                    .filter(|mode| *mode <= 0o7777)
                    .ok_or_else(|| format!("chmod: {mode} is not an octal mode"))?;
                let target = self.resolve(path);
                context("chmod", &target, self.sftp.setstat(&target, &Attrs::with_permissions(mode)))?;
            }
            "df" => self.df(rest)?,
            other => return Err(format!("Invalid command {other:?}; try help").into()),
        }
        Ok(Flow::Continue)
    }

    fn cd(&mut self, rest: &[String]) -> Result<(), Failure> {
        let target = match rest {
            [] => self.home.clone(),
            [path] => self.resolve(path),
            _ => return Err("usage: cd [path]".into()),
        };
        let canonical = context("cd", &target, self.sftp.realpath(&target))?;
        let attrs = context("cd", &canonical, self.sftp.stat(&canonical))?;
        if !attrs.is_dir() {
            return Err(format!("cd {}: Not a directory", display(&canonical)).into());
        }
        self.cwd = canonical;
        Ok(())
    }

    fn ls(&mut self, rest: &[String]) -> Result<(), Failure> {
        let (letters, operands) = flags(rest, "1alh")?;
        let long = letters.contains('l');
        let all = letters.contains('a');
        let target = match operands {
            [] => self.cwd.clone(),
            [path] => self.resolve(path),
            _ => return Err("usage: ls [-1alh] [path]".into()),
        };
        let attrs = context("ls", &target, self.sftp.stat(&target))?;
        let mut entries = if attrs.is_dir() {
            context("ls", &target, self.sftp.read_dir(&target))?
        } else {
            vec![DirEntry {
                name: target.clone(),
                long_name: Vec::new(),
                attrs,
            }]
        };
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        for entry in entries {
            if !all && entry.name.starts_with(b".") && entry.name != target {
                continue;
            }
            if long {
                say(&long_line(&entry, letters.contains('h')));
            } else {
                say(&display(&entry.name));
            }
        }
        Ok(())
    }

    fn transfer(&mut self, rest: &[String], get: bool) -> Result<(), Failure> {
        let name = if get { "get" } else { "put" };
        let (letters, operands) = flags(rest, "prR")?;
        let options = CopyOptions {
            recursive: letters.contains('r') || letters.contains('R'),
            preserve: letters.contains('p'),
        };
        match (get, operands) {
            (true, [remote]) => {
                let remote = self.resolve(remote);
                download(&mut self.sftp, &remote, Path::new("."), options, &mut self.meter)
            }
            (true, [remote, local]) => {
                let remote = self.resolve(remote);
                download(&mut self.sftp, &remote, Path::new(local), options, &mut self.meter)
            }
            (false, [local]) => {
                let cwd = self.cwd.clone();
                upload(&mut self.sftp, Path::new(local), &cwd, options, &mut self.meter)
            }
            (false, [local, remote]) => {
                let remote = self.resolve(remote);
                upload(&mut self.sftp, Path::new(local), &remote, options, &mut self.meter)
            }
            _ => return Err(format!("usage: {name} [-pr] source [destination]").into()),
        }
        .map_err(|error| Failure {
            message: format!("{name}: {error}"),
            fatal: error.is_fatal(),
        })
    }

    fn link(&mut self, command: &str, rest: &[String]) -> Result<(), Failure> {
        let (letters, operands) = if command == "ln" { flags(rest, "s")? } else { (String::from("s"), rest) };
        let [target, link] = operands else {
            return Err(format!("usage: {command} {}target link", if command == "ln" { "[-s] " } else { "" }).into());
        };
        let link_path = self.resolve(link);
        if letters.contains('s') {
            context("ln", &link_path, self.sftp.symlink(target.as_bytes(), &link_path))
        } else {
            let existing = self.resolve(target);
            context("ln", &link_path, self.sftp.hardlink(&existing, &link_path))
        }
    }

    fn df(&mut self, rest: &[String]) -> Result<(), Failure> {
        let (letters, operands) = flags(rest, "hi")?;
        let target = match operands {
            [] => self.cwd.clone(),
            [path] => self.resolve(path),
            _ => return Err("usage: df [-h] [path]".into()),
        };
        let stats = context("df", &target, self.sftp.statvfs(&target))?;
        say(&df_lines(&stats, letters.contains('h')));
        Ok(())
    }
}

fn long_line(entry: &DirEntry, human_sizes: bool) -> String {
    if !entry.long_name.is_empty() {
        return display(&entry.long_name);
    }
    let attrs = &entry.attrs;
    let mode = attrs.permissions.unwrap_or(0);
    let kind = if attrs.is_dir() {
        'd'
    } else if attrs.is_symlink() {
        'l'
    } else {
        '-'
    };
    let mut bits = String::new();
    for shift in [6, 3, 0] {
        let triple = (mode >> shift) & 7;
        bits.push(if triple & 4 != 0 { 'r' } else { '-' });
        bits.push(if triple & 2 != 0 { 'w' } else { '-' });
        bits.push(if triple & 1 != 0 { 'x' } else { '-' });
    }
    let (uid, gid) = attrs.uid_gid.unwrap_or((0, 0));
    let size = attrs.size.unwrap_or(0);
    let size = if human_sizes { human(size) } else { size.to_string() };
    format!("{kind}{bits} {uid:>8} {gid:>8} {size:>10} {}", display(&entry.name))
}

fn df_lines(stats: &StatVfs, human_sizes: bool) -> String {
    let fragment = stats.fragment_size.max(1);
    let total = stats.blocks.saturating_mul(fragment);
    let free = stats.blocks_free.saturating_mul(fragment);
    let available = stats.blocks_available.saturating_mul(fragment);
    let used = total.saturating_sub(free);
    let capacity = if used + available == 0 { 0 } else { used.saturating_mul(100).div_ceil(used + available) };
    let show = |bytes: u64| if human_sizes { human(bytes) } else { (bytes / 1024).to_string() };
    format!(
        "{:>12} {:>12} {:>12} {:>12} {:>5}\n{:>12} {:>12} {:>12} {:>12} {:>4}%",
        "Size", "Used", "Avail", "(root)", "%Capacity",
        show(total), show(used), show(available), show(free), capacity
    )
}

fn script_lines(path: &str) -> Result<Box<dyn BufRead>, String> {
    if path == "-" {
        Ok(Box::new(std::io::BufReader::new(stdin())))
    } else {
        let file = std::fs::File::open(path).map_err(|error| format!("{path}: {error}"))?;
        Ok(Box::new(std::io::BufReader::new(file)))
    }
}

enum Exit {
    Usage(String),
    Run(String),
}

impl From<String> for Exit {
    fn from(message: String) -> Self {
        Self::Run(message)
    }
}

impl From<Failure> for Exit {
    fn from(failure: Failure) -> Self {
        Self::Run(failure.message)
    }
}

fn run() -> Result<u8, Exit> {
    let options = parse(std::env::args().skip(1)).map_err(Exit::Usage)?;
    let batch = match &options.batch {
        Some(path) => Some(script_lines(path)?),
        None => None,
    };
    let sftp = open_sftp(&options.connect, &options.host, &options.user)?;
    let mut shell = Shell {
        sftp,
        cwd: Vec::new(),
        home: Vec::new(),
        meter: Meter::new(stdout()),
    };
    let start = if options.path.is_empty() { ".".to_owned() } else { options.path.clone() };
    shell.home = shell
        .sftp
        .realpath(b".")
        .map_err(|error| format!("cannot find the remote home directory: {error}"))?;
    shell.cwd = shell.home.clone();
    if start != "." {
        shell.cd(&[start])?;
    }

    let abort_on_error = batch.is_some();
    let echo = batch.is_some();
    let prompt = batch.is_none() && stdin().is_terminal();
    let mut input = match batch {
        Some(reader) => reader,
        None => Box::new(std::io::BufReader::new(stdin())),
    };
    let mut status = 0;
    let mut line = String::new();
    loop {
        if prompt {
            print!("sftp> ");
            let _ = stdout().flush();
        }
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("oxish-sftp: reading commands: {error}");
                status = EXIT_FAILURE;
                break;
            }
        }
        let mut text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let ignore_failure = text.starts_with('-');
        if ignore_failure {
            text = text[1..].trim_start();
        }
        if echo {
            say(&format!("sftp> {text}"));
        }
        let outcome = split_words(text)
            .map_err(Failure::from)
            .and_then(|words| shell.run(&words));
        match outcome {
            Ok(Flow::Continue) => {}
            Ok(Flow::Exit) => break,
            Err(failure) => {
                eprintln!("oxish-sftp: {}", failure.message);
                if failure.fatal {
                    return Err(Exit::Run(String::new()));
                }
                if abort_on_error && !ignore_failure {
                    status = EXIT_FAILURE;
                    break;
                }
            }
        }
    }
    shell.sftp.disconnect();
    Ok(status)
}

fn main() -> ExitCode {
    match run() {
        Ok(status) => ExitCode::from(status),
        Err(exit) => {
            match exit {
                Exit::Usage(message) => {
                    if !message.is_empty() {
                        eprintln!("oxish-sftp: {message}");
                    }
                    eprintln!("{USAGE}");
                }
                Exit::Run(message) if !message.is_empty() => eprintln!("oxish-sftp: {message}"),
                Exit::Run(_) => {}
            }
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        split_words(line).expect("splits")
    }

    #[test]
    fn words_honor_quotes_and_escapes() {
        assert_eq!(words("get a b"), ["get", "a", "b"]);
        assert_eq!(words("  get   'a b'  \"c d\" "), ["get", "a b", "c d"]);
        assert_eq!(words(r"put a\ b ''"), ["put", "a b", ""]);
        assert_eq!(words(r#"put "a\"b" "c\d""#), ["put", "a\"b", r"c\d"]);
        assert_eq!(words(r"rm x\\y"), ["rm", r"x\y"]);
        assert!(words("").is_empty());
        assert!(split_words("get 'a").is_err());
        assert!(split_words("get \"a").is_err());
        assert!(split_words("get a\\").is_err());
    }

    #[test]
    fn flags_split_from_operands() {
        let input = words("-pr a b");
        let (letters, rest) = flags(&input, "prR").expect("flags");
        assert_eq!(letters, "pr");
        assert_eq!(rest, ["a", "b"]);
        let input = words("-- -a");
        let (letters, rest) = flags(&input, "p").expect("flags");
        assert_eq!(letters, "");
        assert_eq!(rest, ["-a"]);
        assert!(flags(&words("-x a"), "p").is_err());
    }

    #[test]
    fn the_target_may_carry_a_path_and_a_batch_file() {
        let options = parse(
            "-P 2200 -i k --host-key SHA256:x -b cmds u@h:dir/sub"
                .split_whitespace()
                .map(str::to_owned),
        )
        .expect("parses");
        assert_eq!(options.connect.port, 2200);
        assert_eq!(options.batch.as_deref(), Some("cmds"));
        assert_eq!((options.user.as_str(), options.host.as_str(), options.path.as_str()), ("u", "h", "dir/sub"));
        assert!(parse("-i k u@h".split_whitespace().map(str::to_owned)).is_err());
        assert!(parse("-i k --host-key SHA256:x u@h extra".split_whitespace().map(str::to_owned)).is_err());
    }

    #[test]
    fn long_lines_fall_back_to_the_attributes() {
        let entry = DirEntry {
            name: b"f".to_vec(),
            long_name: Vec::new(),
            attrs: Attrs {
                size: Some(7),
                permissions: Some(0o100_640),
                uid_gid: Some((1, 2)),
                ..Attrs::default()
            },
        };
        assert_eq!(long_line(&entry, false), "-rw-r-----        1        2          7 f");
    }
}
