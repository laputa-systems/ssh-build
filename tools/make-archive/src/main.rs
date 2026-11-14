use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// 1980-01-01T00:00:00Z, the earliest DOS timestamp; releases must not depend on the wall clock.
const FIXED_MTIME: i64 = 315_532_800;

fn valid_entry_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    for byte in name.bytes() {
        if !(0x20..=0x7e).contains(&byte) || byte == 0x5c {
            return false;
        }
    }
    !name
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: make-archive <output.zip> <base-dir> <entry>...");
        return ExitCode::from(2);
    }
    let output = PathBuf::from(&args[1]);
    let base = Path::new(&args[2]);
    let entries = &args[3..];

    match run(&output, base, entries) {
        Ok(count) => {
            println!("make-archive: wrote {} ({count} entries)", output.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("make-archive: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(output: &Path, base: &Path, entries: &[String]) -> Result<usize, String> {
    let base = fs::canonicalize(base).map_err(|error| format!("{}: {error}", base.display()))?;
    if !base.is_dir() {
        return Err(format!("{} is not a directory", base.display()));
    }

    let mut seen = std::collections::HashSet::new();
    let mut prepared = Vec::with_capacity(entries.len());
    for entry in entries {
        if !valid_entry_name(entry) {
            return Err(format!("unsafe archive name {entry}"));
        }
        if !seen.insert(entry.clone()) {
            return Err(format!("duplicate entry {entry}"));
        }
        let source = base.join(entry);
        let metadata = fs::symlink_metadata(&source)
            .map_err(|error| format!("{}: {error}", source.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{entry} is a symlink; archives hold regular files only"));
        }
        if !metadata.is_file() {
            return Err(format!("{entry} is not a regular file"));
        }
        let mode = metadata.permissions().mode();
        let archive_mode = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
        prepared.push((entry.clone(), source, archive_mode));
    }

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
    }

    let file = File::create(output).map_err(|error| format!("{}: {error}", output.display()))?;
    let mut archive = rawzip::ZipArchiveWriter::new(BufWriter::new(file));
    for (entry, source, archive_mode) in &prepared {
        let builder = archive
            .new_file(entry.as_str())
            .compression_method(rawzip::CompressionMethod::DEFLATE)
            .last_modified(rawzip::time::UtcDateTime::from_unix(FIXED_MTIME))
            .unix_permissions(*archive_mode);
        let (mut entry_writer, config) = builder.start().map_err(|error| error.to_string())?;
        let encoder = flate2::write::DeflateEncoder::new(
            &mut entry_writer,
            flate2::Compression::default(),
        );
        let mut writer = config.wrap(encoder);
        let mut input = File::open(source)
            .map_err(|error| format!("{}: {error}", source.display()))?;
        io::copy(&mut input, &mut writer).map_err(|error| format!("{entry}: {error}"))?;
        let (encoder, descriptor) = writer.finish().map_err(|error| error.to_string())?;
        encoder
            .finish()
            .map_err(|error| format!("{entry}: {error}"))?;
        entry_writer
            .finish(descriptor)
            .map_err(|error| error.to_string())?;
    }
    archive.finish().map_err(|error| error.to_string())?;
    Ok(prepared.len())
}
