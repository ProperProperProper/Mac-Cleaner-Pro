//! Listening sockets, DNS, proxies, /etc/hosts, Wi-Fi security.

use super::super::fix::{Fix, Step, admin, pane, settings_fix};
use super::super::{Category::Network, Ctx, Finding, Socket, Status};
use crate::cmd;
use crate::util::sh_quote;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Scope {
    Localhost,
    AllInterfaces,
    Specific,
}

pub fn scope(host: &str) -> Scope {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    if h.starts_with("127.") || h == "::1" || h == "localhost" || h.starts_with("::ffff:127.") {
        Scope::Localhost
    } else if h == "*" || h == "0.0.0.0" || h == "::" || h.is_empty() {
        Scope::AllInterfaces
    } else {
        Scope::Specific
    }
}

fn unescape_lsof(s: &str) -> String {
    s.replace("\\x20", " ")
}

/// Parse `lsof -nP -iTCP -sTCP:LISTEN` or `lsof -nP -iUDP` output.
pub fn parse_lsof(out: &str) -> Vec<Socket> {
    let mut v = vec![];
    for line in out.lines().skip(1) {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = toks.iter().position(|t| *t == "TCP" || *t == "UDP") else { continue };
        let Some(addr) = toks.get(i + 1) else { continue };
        let addr = addr.split("->").next().unwrap_or(addr);
        let Some((host, port)) = addr.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        if toks[i] == "TCP" && !line.contains("(LISTEN)") {
            continue;
        }
        v.push(Socket { proto: toks[i].to_string(), host: host.to_string(), port, process: unescape_lsof(toks[0]) });
    }
    v
}

/// Parse `netstat -anv -p tcp|udp` output (shows all processes, including root's).
pub fn parse_netstat(out: &str) -> Vec<Socket> {
    let mut v = vec![];
    for line in out.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 5 {
            continue;
        }
        let proto = if toks[0].starts_with("tcp") {
            "TCP"
        } else if toks[0].starts_with("udp") {
            "UDP"
        } else {
            continue;
        };
        if proto == "TCP" && toks.get(5) != Some(&"LISTEN") {
            continue;
        }
        let Some((host, port)) = toks[3].rsplit_once('.') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let process = toks[4..]
            .iter()
            .find_map(|t| {
                let (name, pid) = t.rsplit_once(':')?;
                (!name.is_empty() && !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) && !name.chars().all(|c| c.is_ascii_digit()))
                    .then(|| name.to_string())
            })
            .unwrap_or_else(|| "?".into());
        v.push(Socket { proto: proto.into(), host: host.to_string(), port, process });
    }
    v
}

/// Merge lsof and netstat views (lsof only sees this user's processes).
pub fn collect_sockets() -> Result<Vec<Socket>, String> {
    let mut set: BTreeSet<Socket> = BTreeSet::new();
    let mut any_ok = false;
    for args in [&["-nP", "-iTCP", "-sTCP:LISTEN"][..], &["-nP", "-iUDP"][..]] {
        if let Ok(o) = cmd::run_timeout("lsof", args, Duration::from_secs(20)) {
            any_ok = true;
            set.extend(parse_lsof(&o.stdout));
        }
    }
    for p in ["tcp", "udp"] {
        if let Ok(o) = cmd::run("netstat", &["-anv", "-p", p]) {
            any_ok = true;
            for s in parse_netstat(&o.stdout) {
                let dup = set.iter().any(|x| x.proto == s.proto && x.port == s.port && scope(&x.host) == scope(&s.host));
                if !dup {
                    set.insert(s);
                }
            }
        }
    }
    if any_ok { Ok(set.into_iter().collect()) } else { Err("lsof and netstat both unavailable".into()) }
}

pub fn known_service(proto: &str, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        ("TCP", 22) => "SSH / Remote Login",
        ("TCP", 5900) => "Screen Sharing (VNC)",
        ("TCP", 445) => "File Sharing (SMB)",
        ("TCP", 548) => "File Sharing (AFP)",
        ("TCP", 3283) | ("UDP", 3283) => "Apple Remote Desktop",
        ("TCP", 5000) | ("TCP", 7000) => "AirPlay Receiver",
        ("TCP", 631) => "Printer Sharing (CUPS)",
        ("TCP", 3031) => "Remote Apple Events",
        ("TCP", 88) => "Kerberos (Screen Sharing auth)",
        ("UDP", 5353) => "Bonjour / mDNS",
        ("UDP", 137) | ("UDP", 138) => "NetBIOS (SMB)",
        ("UDP", 123) => "NTP time sync",
        _ => return None,
    })
}

pub const APPLE_DAEMONS: [&str; 12] = [
    "rapportd", "sharingd", "ControlCe", "ControlCenter", "identitys", "identityservicesd", "mDNSRespo", "mDNSResponder",
    "UniversalControl", "remoted", "AirPlayXPCHelper", "replicatord",
];

pub fn is_apple_daemon(p: &str) -> bool {
    APPLE_DAEMONS.iter().any(|a| p.starts_with(a)) || p == "replicato" || p == "launchd"
}

fn describe(s: &Socket) -> String {
    let svc = known_service(&s.proto, s.port).map(|n| format!(" — {n}")).unwrap_or_default();
    format!("{} {}:{} ({}){svc}", s.proto, s.host, s.port, s.process)
}

/// Collapse IPv4/IPv6 duplicates for display.
fn dedupe(v: Vec<&Socket>) -> Vec<&Socket> {
    let mut seen = BTreeSet::new();
    v.into_iter().filter(|s| seen.insert((s.proto.clone(), s.port, s.process.clone()))).collect()
}

pub fn listeners(ctx: &Ctx) -> Vec<Finding> {
    let socks = match ctx.sockets() {
        Ok(s) => s,
        Err(e) => return vec![Finding::unknown(Network, "Listening network services", e)],
    };
    let exposed_tcp = dedupe(socks.iter().filter(|s| s.proto == "TCP" && scope(&s.host) != Scope::Localhost).collect());
    let local_tcp = dedupe(socks.iter().filter(|s| s.proto == "TCP" && scope(&s.host) == Scope::Localhost).collect());
    let exposed_udp = dedupe(socks.iter().filter(|s| s.proto == "UDP" && scope(&s.host) != Scope::Localhost).collect());

    let mut out = vec![];
    let t = "Services reachable from the network (TCP)";
    let why = "Anything listening on all interfaces can be reached by other devices on the same network (home, office, café Wi-Fi). Each one is a potential way in. Local-only (127.0.0.1) services are not reachable from other machines.";
    let review: Vec<&&Socket> = exposed_tcp.iter().filter(|s| !is_apple_daemon(&s.process) || known_service("TCP", s.port).is_some()).collect();
    out.push(if exposed_tcp.is_empty() {
        Finding::new(Network, t, Status::Ok, "Nothing is listening for TCP connections from other devices.").explain(why)
    } else if review.is_empty() {
        Finding::new(Network, t, Status::Info, format!("{} Apple system service(s) listening (Continuity/Handoff).", exposed_tcp.len()))
            .evidence_all(exposed_tcp.iter().map(|s| describe(s)))
            .explain(why)
    } else {
        Finding::new(Network, t, Status::Warning, format!("{} service(s) accept connections from other devices — review.", review.len()))
            .evidence_all(exposed_tcp.iter().map(|s| describe(s)))
            .explain(why)
            .fix_text("For your own servers, bind them to 127.0.0.1 instead of 0.0.0.0. Turn off sharing services you don't use (see Sharing). Keep the firewall on.")
            .command("lsof -nP -iTCP -sTCP:LISTEN")
            .with_fix(settings_fix("Open Sharing settings", pane::SHARING, "Turn off any sharing service you don't use."))
    });
    out.push(
        Finding::new(Network, "Local-only services (TCP)", if local_tcp.is_empty() { Status::Ok } else { Status::Info },
            format!("{} service(s) listen on localhost only (not reachable from other machines).", local_tcp.len()))
        .evidence_all(local_tcp.iter().map(|s| describe(s)))
        .explain("Informational: local dev servers, databases and helpers bound to 127.0.0.1."),
    );
    out.push(
        Finding::new(Network, "UDP ports open to the network", Status::Info, format!("{} UDP port(s) bound on all interfaces.", exposed_udp.len()))
            .evidence_all(exposed_udp.iter().map(|s| describe(s)))
            .explain("Mostly Apple discovery services (Bonjour, AirDrop, Continuity). Note: without admin rights some root-owned sockets may not be attributed to a process."),
    );
    out
}

/// Unique nameservers from `scutil --dns`.
pub fn parse_scutil_dns(out: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for l in out.lines() {
        if l.trim_start().starts_with("nameserver[")
            && let Some((_, ip)) = l.split_once(':')
        {
            let ip = ip.trim().to_string();
            if !v.contains(&ip) {
                v.push(ip);
            }
        }
    }
    v
}

pub fn dns(_: &Ctx) -> Vec<Finding> {
    let t = "DNS servers";
    match cmd::run("scutil", &["--dns"]) {
        Err(e) => vec![Finding::unknown(Network, t, e.to_string())],
        Ok(o) => {
            let ns = parse_scutil_dns(&o.stdout);
            if ns.is_empty() {
                return vec![Finding::new(Network, t, Status::Info, "No DNS servers configured (offline?).")];
            }
            vec![Finding::new(Network, t, Status::Info, format!("Using: {}", ns.join(", ")))
                .evidence_all(ns.iter().map(|n| format!("nameserver {n}")))
                .explain("Your DNS server sees every domain you visit and could redirect you. Check you recognise these (router, ISP, 1.1.1.1/8.8.8.8/9.9.9.9, a local resolver like dnscrypt-proxy on 127.0.0.1, or your VPN). Malware sometimes changes DNS.")
                .fix_text("System Settings → Network → (your connection) → Details → DNS.")
                .with_fix(settings_fix("Open Network settings", pane::NETWORK, "Select your connection → Details → DNS and remove servers you don't recognise."))]
        }
    }
}

/// Enabled proxies from `scutil --proxy`.
pub fn parse_scutil_proxy(out: &str) -> Vec<String> {
    let get = |k: &str| {
        out.lines()
            .find(|l| l.trim_start().starts_with(&format!("{k} :")))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    };
    let mut v = vec![];
    for (en, host, port, name) in [
        ("HTTPEnable", "HTTPProxy", "HTTPPort", "Web proxy (HTTP)"),
        ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "Secure web proxy (HTTPS)"),
        ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS proxy"),
    ] {
        if get(en).as_deref() == Some("1") {
            v.push(format!("{name}: {}:{}", get(host).unwrap_or_default(), get(port).unwrap_or_default()));
        }
    }
    if get("ProxyAutoConfigEnable").as_deref() == Some("1") {
        v.push(format!("Automatic proxy config (PAC): {}", get("ProxyAutoConfigURLString").unwrap_or_default()));
    }
    v
}

pub fn proxies(_: &Ctx) -> Vec<Finding> {
    let t = "Web/SOCKS proxies";
    match cmd::run("scutil", &["--proxy"]) {
        Err(e) => vec![Finding::unknown(Network, t, e.to_string())],
        Ok(o) => {
            let p = parse_scutil_proxy(&o.stdout);
            let why = "A proxy sees (and can tamper with) your web traffic. Adware and malware set proxies to intercept browsing.";
            vec![if p.is_empty() {
                Finding::new(Network, t, Status::Ok, "No proxies configured.").explain(why)
            } else {
                Finding::new(Network, t, Status::Warning, format!("{} proxy setting(s) active — confirm you set them.", p.len()))
                    .evidence_all(p)
                    .explain(why)
                    .fix_text("System Settings → Network → (connection) → Details → Proxies → turn off any you don't recognise.")
                    .with_fix(settings_fix("Open Network settings", pane::NETWORK, "Select your connection → Details → Proxies and turn off unknown proxies."))
            }]
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HostEntry {
    pub ip: String,
    pub names: Vec<String>,
    pub line: String,
}

pub fn parse_hosts(content: &str) -> Vec<HostEntry> {
    let defaults = [("127.0.0.1", "localhost"), ("255.255.255.255", "broadcasthost"), ("::1", "localhost"), ("fe80::1%lo0", "localhost")];
    content
        .lines()
        .filter_map(|l| {
            let body = l.split('#').next().unwrap_or("").trim();
            let mut it = body.split_whitespace();
            let ip = it.next()?.to_string();
            let names: Vec<String> = it.map(|s| s.to_string()).collect();
            if names.is_empty() || (names.len() == 1 && defaults.contains(&(ip.as_str(), names[0].as_str()))) {
                return None;
            }
            Some(HostEntry { ip, names, line: l.to_string() })
        })
        .collect()
}

pub const SENSITIVE_DOMAINS: [&str; 12] = [
    "apple.com", "icloud.com", "mzstatic.com", "google.", "microsoft.com", "github.com", "paypal.", "bank", "objective-see", "malwarebytes", "virustotal", "windowsupdate",
];

pub fn is_sensitive(e: &HostEntry) -> bool {
    e.names.iter().any(|n| SENSITIVE_DOMAINS.iter().any(|d| n.to_lowercase().contains(d)))
}

/// /etc/hosts content with the given lines removed.
pub fn hosts_without(content: &str, remove: &[HostEntry]) -> String {
    let drop: Vec<&str> = remove.iter().map(|e| e.line.as_str()).collect();
    let mut s: String = content.lines().filter(|l| !drop.contains(l)).collect::<Vec<_>>().join("\n");
    s.push('\n');
    s
}

pub fn hosts(ctx: &Ctx) -> Vec<Finding> {
    let t = "/etc/hosts";
    let content = match std::fs::read_to_string("/etc/hosts") {
        Ok(c) => c,
        Err(e) => return vec![Finding::unknown(Network, t, e.to_string())],
    };
    let extra = parse_hosts(&content);
    let why = "/etc/hosts overrides DNS. Malware uses it to redirect banking/Apple/security sites or to block security updates.";
    if extra.is_empty() {
        return vec![Finding::new(Network, t, Status::Ok, "Only the default entries.").explain(why)];
    }
    let sens: Vec<HostEntry> = extra.iter().filter(|e| is_sensitive(e)).cloned().collect();
    let ev = extra.iter().map(|e| format!("{} → {}", e.names.join(" "), e.ip)).collect::<Vec<_>>();
    if sens.is_empty() {
        return vec![Finding::new(Network, t, Status::Info, format!("{} custom entr(ies) — none for sensitive domains.", extra.len())).evidence_all(ev).explain(why)];
    }
    let backup = format!("/etc/hosts.mac-cleaner-pro-{}", ctx.stamp);
    let staged = ctx.backup_dir().join(format!("hosts-cleaned-{}", ctx.stamp)).display().to_string();
    let mut fx = Fix::new("Remove suspicious /etc/hosts entries")
        .step(Step::WriteFile { path: staged.clone(), content: hosts_without(&content, &sens) })
        .step(admin(format!(
            "/bin/cp -p /etc/hosts {b} && /bin/cp {s} /etc/hosts && /usr/sbin/chown root:wheel /etc/hosts && /bin/chmod 644 /etc/hosts && /usr/bin/dscacheutil -flushcache && /usr/bin/killall -HUP mDNSResponder",
            b = sh_quote(&backup),
            s = sh_quote(&staged)
        )))
        .undo(vec![admin(format!("/bin/cp -p {} /etc/hosts && /usr/bin/dscacheutil -flushcache", sh_quote(&backup)))]);
    for e in &sens {
        fx = fx.change(format!("Remove line: {}", e.line.trim()));
    }
    vec![Finding::new(Network, t, Status::Warning, format!("{} entr(ies) override sensitive domains — review.", sens.len()))
        .evidence_all(ev)
        .explain(why)
        .fix_text("Remove the lines you didn't add (a backup is kept).")
        .command("sudo nano /etc/hosts")
        .with_fix(fx)]
}

/// Security type of the current Wi-Fi network (SSID is never read or shown).
pub fn parse_wifi_security(out: &str) -> Option<String> {
    let idx = out.find("Current Network Information:")?;
    let rest = &out[idx..];
    let end = rest.find("Other Local Wi-Fi Networks:").unwrap_or(rest.len());
    rest[..end]
        .lines()
        .find_map(|l| l.trim().strip_prefix("Security:").map(|s| s.trim().to_string()))
}

pub fn wifi(_: &Ctx) -> Vec<Finding> {
    let t = "Wi-Fi security";
    let o = match cmd::run_timeout("system_profiler", &["SPAirPortDataType"], Duration::from_secs(60)) {
        Ok(o) => o,
        Err(e) => return vec![Finding::unknown(Network, t, e.to_string())],
    };
    let why = "On open or WEP/WPA1 networks, others nearby can read or tamper with unencrypted traffic.";
    vec![match parse_wifi_security(&o.stdout) {
        None => Finding::new(Network, t, Status::Info, "Not connected to Wi-Fi (or Wi-Fi off).").explain(why),
        Some(s) => {
            let l = s.to_lowercase();
            if l.contains("wpa3") || l.contains("wpa2") {
                Finding::new(Network, t, Status::Ok, format!("Current network uses {s}.")).evidence(format!("Security: {s}")).explain(why)
            } else {
                Finding::new(Network, t, Status::Warning, format!("Current network uses weak/no encryption: {s}."))
                    .evidence(format!("Security: {s}"))
                    .explain(why)
                    .fix_text("Use a VPN on this network, or switch the router to WPA2/WPA3.")
                    .with_fix(settings_fix("Open Wi-Fi settings", pane::WIFI, "Prefer a WPA2/WPA3 network."))
            }
        }
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    const LSOF: &str = "COMMAND     PID        USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nrapportd    616 me   10u  IPv4   0xefb4c61e332435      0t0  TCP *:64456 (LISTEN)\nollama     1003 me    3u  IPv4 0x72b4dc7cd7300bda      0t0  TCP 127.0.0.1:11434 (LISTEN)\nControlCe   700 me    9u  IPv6 0x1      0t0  TCP [::1]:7000 (LISTEN)\nGoogle\\x20C  9 me 1u IPv4 0x2 0t0 TCP *:5000 (LISTEN)\n";
    const LSOF_UDP: &str = "COMMAND   PID        USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nidentitys 625 me    8u  IPv4 0xd68503f4eb4b2b14      0t0  UDP *:*\nsharingd  626 me   11u  IPv6  0x5b41ff8306e21fd      0t0  UDP *:50674\n";
    const NETSTAT: &str = "tcp4       0      0  127.0.0.1.8789         *.*                    LISTEN                 0            0  131072  131072              bot:5257   00100 00000006 0000000000161026 00000001 00000800      1      0 000000\ntcp6       0      0  *.64456                *.*                    LISTEN                 0            0  131072  131072         rapportd:616    00100 00000006 000000000001ee0c 00000001 00000800      1      0 000000\ntcp4       0      0  192.168.1.5.443  1.2.3.4.5555  ESTABLISHED 0 0 1 1 x:1\nudp4       0      0  *.*                    *.*                               \nudp46      0      0  *.50674                *.*      0 0 1 1 sharingd:626\n";

    #[test]
    fn lsof_tcp() {
        let v = parse_lsof(LSOF);
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], Socket { proto: "TCP".into(), host: "*".into(), port: 64456, process: "rapportd".into() });
        assert_eq!(scope(&v[1].host), Scope::Localhost);
        assert_eq!(scope(&v[2].host), Scope::Localhost);
        assert_eq!(v[3].process, "Google C");
    }

    #[test]
    fn lsof_udp_skips_unbound() {
        let v = parse_lsof(LSOF_UDP);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].port, 50674);
    }

    #[test]
    fn netstat() {
        let v = parse_netstat(NETSTAT);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Socket { proto: "TCP".into(), host: "127.0.0.1".into(), port: 8789, process: "bot".into() });
        assert_eq!(v[1].process, "rapportd");
        assert_eq!(scope(&v[1].host), Scope::AllInterfaces);
        assert_eq!(v[2].proto, "UDP");
    }

    #[test]
    fn scopes_and_services() {
        assert_eq!(scope("0.0.0.0"), Scope::AllInterfaces);
        assert_eq!(scope("192.168.1.2"), Scope::Specific);
        assert_eq!(known_service("TCP", 5000), Some("AirPlay Receiver"));
        assert_eq!(known_service("TCP", 22), Some("SSH / Remote Login"));
        assert!(is_apple_daemon("rapportd"));
        assert!(!is_apple_daemon("ollama"));
    }

    #[test]
    fn dns_parse() {
        let s = "DNS configuration\n\nresolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 9.9.9.9\nresolver #2\n  nameserver[0] : 1.1.1.1\n";
        assert_eq!(parse_scutil_dns(s), vec!["1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn proxy_parse() {
        let none = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  FTPPassive : 1\n}\n";
        assert!(parse_scutil_proxy(none).is_empty());
        let some = "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : 10.0.0.9\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/x.pac\n}\n";
        let p = parse_scutil_proxy(some);
        assert_eq!(p, vec!["Web proxy (HTTP): 10.0.0.9:8080", "Automatic proxy config (PAC): http://wpad/x.pac"]);
    }

    #[test]
    fn hosts_parse_and_clean() {
        let c = "##\n# Host Database\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n127.0.0.1 myapp.test\n0.0.0.0 swscan.apple.com # block\n";
        let e = parse_hosts(c);
        assert_eq!(e.len(), 2);
        assert!(!is_sensitive(&e[0]));
        assert!(is_sensitive(&e[1]));
        let cleaned = hosts_without(c, &e[1..]);
        assert!(!cleaned.contains("apple.com"));
        assert!(cleaned.contains("myapp.test"));
        assert!(cleaned.contains("localhost"));
    }

    #[test]
    fn wifi_parse() {
        let s = "Wi-Fi:\n      Interfaces:\n        en0:\n          Current Network Information:\n            HomeNet:\n              PHY Mode: 802.11ax\n              Security: WPA2 Personal\n          Other Local Wi-Fi Networks:\n            Cafe:\n              Security: None\n";
        assert_eq!(parse_wifi_security(s).as_deref(), Some("WPA2 Personal"));
        assert_eq!(parse_wifi_security("Wi-Fi:\n  Other Local Wi-Fi Networks:\n    Security: None\n"), None);
    }
}
