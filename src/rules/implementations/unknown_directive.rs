use glob::{MatchOptions, Pattern};

use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

/// Errors on directives unknown to current portable OpenSSH, while respecting
/// earlier IgnoreUnknown patterns and common platform extensions.
pub struct UnknownDirective;

const KNOWN_DIRECTIVES: &[&str] = &[
    "AddKeysToAgent",
    "AddressFamily",
    "AFSTokenPassing",
    "BatchMode",
    "BindAddress",
    "BindInterface",
    "CanonicalDomains",
    "CanonicalizeFallbackLocal",
    "CanonicalizeHostname",
    "CanonicalizeMaxDots",
    "CanonicalizePermittedCNAMEs",
    "CASignatureAlgorithms",
    "CertificateFile",
    "ChallengeResponseAuthentication",
    "ChannelTimeout",
    "CheckHostIP",
    "Cipher",
    "Ciphers",
    "ClearAllForwardings",
    "Compression",
    "CompressionLevel",
    "ConnectionAttempts",
    "ConnectTimeout",
    "ControlMaster",
    "ControlPath",
    "ControlPersist",
    "DSAAuthentication",
    "DynamicForward",
    "EnableEscapeCommandline",
    "EnableSSHKeysign",
    "EscapeChar",
    "ExitOnForwardFailure",
    "FallbackToRsh",
    "FingerprintHash",
    "ForkAfterAuthentication",
    "ForwardAgent",
    "ForwardX11",
    "ForwardX11Timeout",
    "ForwardX11Trusted",
    "GatewayPorts",
    "GlobalKnownHostsFile",
    "GlobalKnownHostsFile2",
    "GSSAPIAuthentication",
    "GSSAPIDelegateCredentials",
    "HashKnownHosts",
    "Host",
    "HostbasedAcceptedAlgorithms",
    "HostbasedAuthentication",
    "HostbasedKeyTypes",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "Hostname",
    "IdentitiesOnly",
    "IdentityAgent",
    "IdentityFile",
    "IdentityFile2",
    "IgnoreUnknown",
    "Include",
    "IPQoS",
    "KbdInteractiveAuthentication",
    "KbdInteractiveDevices",
    "KeepAlive",
    "KerberosAuthentication",
    "KerberosTGTPassing",
    "KexAlgorithms",
    "KnownHostsCommand",
    "LocalCommand",
    "LocalForward",
    "LogLevel",
    "LogVerbose",
    "MACs",
    "Match",
    "NoHostAuthenticationForLocalhost",
    "NumberOfPasswordPrompts",
    "ObscureKeystrokeTiming",
    "PasswordAuthentication",
    "PermitLocalCommand",
    "PermitRemoteOpen",
    "PKCS11Provider",
    "Port",
    "PreferredAuthentications",
    "Protocol",
    "ProxyCommand",
    "ProxyJump",
    "ProxyUseFdpass",
    "PubkeyAcceptedAlgorithms",
    "PubkeyAcceptedKeyTypes",
    "PubkeyAuthentication",
    "RefuseConnection",
    "RekeyLimit",
    "RemoteCommand",
    "RemoteForward",
    "RequestTTY",
    "RequiredRSASize",
    "RevokedHostKeys",
    "RhostsAuthentication",
    "RhostsRSAAuthentication",
    "RSAAuthentication",
    "SecurityKeyProvider",
    "SendEnv",
    "ServerAliveCountMax",
    "ServerAliveInterval",
    "SessionType",
    "SetEnv",
    "SkeyAuthentication",
    "SmartcardDevice",
    "StdinNull",
    "StreamLocalBindMask",
    "StreamLocalBindUnlink",
    "StrictHostKeyChecking",
    "SyslogFacility",
    "Tag",
    "TCPKeepAlive",
    "TISAuthentication",
    "Tunnel",
    "TunnelDevice",
    "UpdateHostKeys",
    "UsePrivilegedPort",
    "User",
    "UserKnownHostsFile",
    "UserKnownHostsFile2",
    "UseRoaming",
    "UserSH",
    "VerifyHostKeyDNS",
    "VersionAddendum",
    "VisualHostKey",
    "WarnWeakCrypto",
    "XAuthLocation",
    // Common vendor extensions. Portable configs usually guard these with
    // IgnoreUnknown, but recognising them avoids platform-specific noise.
    "UseKeychain",
    "AppleMultipath",
    "NoHostAuthenticationForProxyCommand",
];

impl Rule for UnknownDirective {
    fn name(&self) -> &'static str {
        "unknown-directive"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut ignored_patterns = Vec::new();
        collect(&config.items, &mut ignored_patterns, &mut findings);
        findings
    }
}

fn collect(items: &[Item], ignored_patterns: &mut Vec<String>, findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive { key, value, .. } if key.eq_ignore_ascii_case("IgnoreUnknown") => {
                if let Some(arguments) = parse_value_arguments(value) {
                    if let [argument] = arguments.as_slice() {
                        ignored_patterns.push(argument.to_ascii_lowercase());
                    }
                }
            }
            Item::Directive { key, span, .. } if !is_known(key) => {
                if ignored_patterns
                    .iter()
                    .any(|patterns| pattern_list_matches(key, patterns))
                {
                    continue;
                }

                let mut finding = Finding::new(
                    Severity::Error,
                    "unknown-directive",
                    "UNKNOWN_DIRECTIVE",
                    format!("unknown SSH client configuration directive: {key}"),
                    span.clone(),
                );
                finding = if let Some(suggestion) = nearest_directive(key) {
                    finding.with_hint(format!("did you mean {suggestion}?"))
                } else {
                    finding.with_hint(
                        "check the spelling or guard a platform-specific option with IgnoreUnknown",
                    )
                };
                findings.push(finding);
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect(items, ignored_patterns, findings);
            }
            _ => {}
        }
    }
}

fn is_known(key: &str) -> bool {
    KNOWN_DIRECTIVES
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
}

fn pattern_list_matches(key: &str, list: &str) -> bool {
    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    let mut positive = false;

    for raw_pattern in list.split(',').filter(|pattern| !pattern.is_empty()) {
        let (negated, pattern) = raw_pattern
            .strip_prefix('!')
            .map_or((false, raw_pattern), |pattern| (true, pattern));
        let matches = Pattern::new(pattern).is_ok_and(|pattern| pattern.matches_with(key, options));
        if matches && negated {
            return false;
        }
        positive |= matches;
    }

    positive
}

fn nearest_directive(key: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let (candidate, distance) = KNOWN_DIRECTIVES
        .iter()
        .map(|candidate| {
            (
                *candidate,
                edit_distance(&key, &candidate.to_ascii_lowercase()),
            )
        })
        .min_by_key(|(_, distance)| *distance)?;
    let threshold = 2.max(key.chars().count() / 3);
    (distance <= threshold).then_some(candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut current = vec![left_index + 1];
        for (right_index, right_char) in right_chars.iter().enumerate() {
            current.push(
                (current[right_index] + 1)
                    .min(previous[right_index + 1] + 1)
                    .min(previous[right_index] + usize::from(left_char != *right_char)),
            );
        }
        previous = current;
    }

    previous[right_chars.len()]
}

#[cfg(test)]
mod tests {
    use super::{edit_distance, pattern_list_matches};

    #[test]
    fn edit_distance_handles_insertions_deletions_and_substitutions() {
        assert_eq!(edit_distance("hostname", "hosname"), 1);
        assert_eq!(edit_distance("identityfile", "identitfile"), 1);
        assert_eq!(edit_distance("proxyjump", "proxijump"), 1);
    }

    #[test]
    fn ignore_patterns_support_wildcards_commas_negation_and_case_folding() {
        assert!(pattern_list_matches("UseKeychain", "usekey*,future*"));
        assert!(!pattern_list_matches("UseKeychain", "usekey*,!usekeychain"));
        assert!(!pattern_list_matches("Other", "usekey*,future*"));
    }
}
