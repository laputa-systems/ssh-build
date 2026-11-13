use std::process::Command;
use oxish_client::KnownHosts;
use oxish_client::known_hosts::Verdict;

#[test]
fn host_matching_agrees_with_openssh_keygen_for_every_pattern_and_endpoint() {
    let blob_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEhJZW5lZ2VyZ2VyZ2VyZ2VyZ2VyZ2VyZ2VyZ2VyZ2Vy";
    let blob = data_encoding::BASE64.decode(blob_b64.as_bytes()).unwrap();
    let patterns = [
        "*.example,!secret.example", "[web.example]:2222", "web?", "WEB.EXAMPLE", "10.0.0.*", "*",
        "!x", "[*.ex]:22", "[*.ex]:2222", "a*b*c", "*?*", "web.example,!web.example", "!web.example,web.example",
        "[::1]:2222", "::1", "[10.0.0.?]:22",
    ];
    let queries = [
        ("web.example", 22), ("web.example", 2222), ("secret.example", 22), ("webx", 22), ("Web.Example", 22),
        ("10.0.0.7", 22), ("x", 22), ("a.ex", 22), ("a.ex", 2222), ("abxbc", 22), ("::1", 2222), ("::1", 22), ("10.0.0.9", 22), ("", 22),
    ];
    let dir = tempfile::tempdir().unwrap();
    let mut mismatches = Vec::new();
    for pattern in patterns {
        let file = dir.path().join("kh");
        let line = format!("{pattern} ssh-ed25519 {blob_b64}\n");
        std::fs::write(&file, &line).unwrap();
        let hosts = KnownHosts::parse(&line).unwrap();
        for (host, port) in queries {
            let name = if port == 22 { host.to_owned() } else { format!("[{host}]:{port}") };
            let out = Command::new("ssh-keygen").args(["-F", &name, "-f"]).arg(&file).output().unwrap();
            let theirs = out.status.success();
            let verdict = hosts.judge(host, port, &blob);
            let ours = matches!(verdict, Verdict::Trusted | Verdict::Changed);
            if theirs != ours { mismatches.push(format!("pattern {pattern:?} query {name:?}: ssh-keygen {theirs} ours {verdict:?}")); }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
