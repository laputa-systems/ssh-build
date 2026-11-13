use std::path::Path;

use data_encoding::BASE64;

use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    revoked: bool,
    patterns: Vec<String>,
    blob: Vec<u8>,
}

/// Host keys read from an OpenSSH `known_hosts` file.
///
/// Plain host names, `[host]:port` forms, comma lists, `*` and `?` wildcards,
/// `!` negation and `@revoked` markers are honored. Hashed entries and
/// `@cert-authority` markers are refused rather than skipped, so a file that
/// relies on them never silently trusts less or more than its author meant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

/// What a `known_hosts` file says about the key a server presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// An entry for this endpoint lists exactly this key.
    Trusted,
    /// A `@revoked` entry for this endpoint lists this key.
    Revoked,
    /// Entries exist for this endpoint, and none lists this key.
    Changed,
    /// No entry names this endpoint.
    Unknown,
}

fn invalid(line: usize, detail: &str) -> Error {
    Error::InvalidTrust {
        detail: format!("known_hosts line {line}: {detail}"),
    }
}

fn unsupported(line: usize, detail: &str) -> Error {
    Error::UnsupportedTrust {
        detail: format!("known_hosts line {line}: {detail}"),
    }
}

impl KnownHosts {
    /// Read and parse a `known_hosts` file.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|error| Error::InvalidTrust {
            detail: format!("cannot read {}: {error}", path.display()),
        })?;
        Self::parse(&text)
    }

    /// Parse `known_hosts` text, refusing anything this client cannot honor.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let mut first = fields.next().ok_or_else(|| invalid(number, "empty entry"))?;
            let mut revoked = false;
            if first.starts_with('@') {
                match first {
                    "@revoked" => revoked = true,
                    "@cert-authority" => {
                        return Err(unsupported(number, "certificate authorities are not supported"));
                    }
                    _ => return Err(invalid(number, "unknown marker")),
                }
                first = fields.next().ok_or_else(|| invalid(number, "marker without a host"))?;
            }
            if first.starts_with('|') {
                return Err(unsupported(number, "hashed host names are not supported"));
            }
            let key_type = fields.next().ok_or_else(|| invalid(number, "missing key type"))?;
            let encoded = fields.next().ok_or_else(|| invalid(number, "missing key"))?;
            let blob = BASE64
                .decode(encoded.as_bytes())
                .map_err(|_| invalid(number, "key is not base64"))?;
            let declared = blob
                .get(4..)
                .zip(blob.get(..4))
                .and_then(|(rest, length)| {
                    let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
                    rest.get(..length)
                })
                .ok_or_else(|| invalid(number, "key blob is truncated"))?;
            if declared != key_type.as_bytes() {
                return Err(invalid(number, "key type differs from the key blob"));
            }
            let patterns = first
                .split(',')
                .map(|pattern| pattern.to_ascii_lowercase())
                .collect::<Vec<_>>();
            if patterns.iter().any(|pattern| pattern.is_empty() || pattern == "!") {
                return Err(invalid(number, "empty host pattern"));
            }
            entries.push(Entry {
                revoked,
                patterns,
                blob,
            });
        }
        Ok(Self { entries })
    }

    /// Judge the key a server presented for an endpoint.
    pub fn judge(&self, host: &str, port: u16, blob: &[u8]) -> Verdict {
        let name = if port == 22 {
            host.to_ascii_lowercase()
        } else {
            format!("[{}]:{port}", host.to_ascii_lowercase())
        };
        let mut named = false;
        let mut trusted = false;
        for entry in self.entries.iter().filter(|entry| entry.matches(&name)) {
            if entry.blob == blob {
                if entry.revoked {
                    return Verdict::Revoked;
                }
                trusted = true;
            } else if !entry.revoked {
                named = true;
            }
        }
        match (trusted, named) {
            (true, _) => Verdict::Trusted,
            (false, true) => Verdict::Changed,
            (false, false) => Verdict::Unknown,
        }
    }
}

impl Entry {
    fn matches(&self, name: &str) -> bool {
        let mut matched = false;
        for pattern in &self.patterns {
            match pattern.strip_prefix('!') {
                Some(negated) if glob(negated, name) => return false,
                Some(_) => {}
                None => matched |= glob(pattern, name),
            }
        }
        matched
    }
}

fn glob(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            backtrack = Some((p, n));
            p += 1;
        } else if let Some((star, matched)) = backtrack {
            p = star + 1;
            n = matched + 1;
            backtrack = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(label: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&(label.len() as u32).to_be_bytes());
        blob.extend_from_slice(label.as_bytes());
        blob
    }

    fn line(hosts: &str, label: &str) -> String {
        format!("{hosts} ssh-ed25519 {}\n", BASE64.encode(&blob(label)))
    }

    #[test]
    fn a_listed_key_is_trusted_for_its_host_only() {
        let hosts = KnownHosts::parse(&line("web.example", "a")).expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Trusted);
        assert_eq!(hosts.judge("WEB.example", 22, &blob("a")), Verdict::Trusted);
        assert_eq!(hosts.judge("db.example", 22, &blob("a")), Verdict::Unknown);
    }

    #[test]
    fn a_different_key_for_a_known_host_is_a_change_not_an_unknown() {
        let hosts = KnownHosts::parse(&line("web.example", "a")).expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("b")), Verdict::Changed);
    }

    #[test]
    fn nonstandard_ports_need_the_bracket_form() {
        let text = line("web.example", "a") + &line("[web.example]:2222", "b");
        let hosts = KnownHosts::parse(&text).expect("parses");
        assert_eq!(hosts.judge("web.example", 2222, &blob("b")), Verdict::Trusted);
        assert_eq!(hosts.judge("web.example", 2222, &blob("a")), Verdict::Changed);
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Trusted);
        assert_eq!(hosts.judge("web.example", 2223, &blob("b")), Verdict::Unknown);
    }

    #[test]
    fn wildcards_negation_and_lists_follow_openssh() {
        let hosts = KnownHosts::parse(&line("*.example,!secret.example,10.0.0.?", "a")).expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Trusted);
        assert_eq!(hosts.judge("secret.example", 22, &blob("a")), Verdict::Unknown);
        assert_eq!(hosts.judge("10.0.0.7", 22, &blob("a")), Verdict::Trusted);
        assert_eq!(hosts.judge("10.0.0.17", 22, &blob("a")), Verdict::Unknown);
    }

    #[test]
    fn a_revocation_overrides_a_trusting_line() {
        let text = line("web.example", "a") + &format!("@revoked {}", line("*", "a"));
        let hosts = KnownHosts::parse(&text).expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Revoked);
        assert_eq!(hosts.judge("web.example", 22, &blob("b")), Verdict::Changed);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let text = format!("# trusted\n\n{}   \n", line("web.example", "a").trim_end());
        let hosts = KnownHosts::parse(&text).expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Trusted);
    }

    #[test]
    fn hashed_and_certificate_authority_entries_are_refused() {
        let hashed = line("|1|c2FsdA==|aGFzaA==", "a");
        assert!(matches!(KnownHosts::parse(&hashed), Err(Error::UnsupportedTrust { .. })));
        let authority = format!("@cert-authority {}", line("*.example", "a"));
        assert!(matches!(KnownHosts::parse(&authority), Err(Error::UnsupportedTrust { .. })));
    }

    #[test]
    fn malformed_trust_material_fails_closed() {
        for bad in [
            "web.example ssh-ed25519\n",
            "web.example ssh-ed25519 not*base64\n",
            "web.example ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIA==\n",
            "@bogus web.example ssh-ed25519 AAAA\n",
            "web.example,,x ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAA==\n",
        ] {
            assert!(
                matches!(KnownHosts::parse(bad), Err(Error::InvalidTrust { .. })),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn arbitrary_text_is_parsed_or_refused_never_panicked_on() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"@|*?!,[]:# \tabcssh-ed25519AAAAC3NzaC1lZDI1NTE5\n=/+";
        for _ in 0..4000 {
            let length = (next() % 120) as usize;
            let text: String = (0..length)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char)
                .collect();
            let _ = KnownHosts::parse(&text);
        }
    }

    #[test]
    fn an_empty_file_trusts_nothing() {
        let hosts = KnownHosts::parse("").expect("parses");
        assert_eq!(hosts.judge("web.example", 22, &blob("a")), Verdict::Unknown);
    }
}
