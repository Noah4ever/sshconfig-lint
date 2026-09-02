use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

#[derive(Clone, Copy)]
enum ValueConstraint {
    UnsignedIntegerRange { min: u64, max: u64 },
    NonNegativeTimeOrNone,
    OctalMask,
    IpQos,
    AllowedValues(&'static [&'static str]),
}

impl ValueConstraint {
    fn accepts(self, value: &str) -> bool {
        let Some(arguments) = parse_value_arguments(value) else {
            return false;
        };

        match self {
            Self::UnsignedIntegerRange { min, max } => match arguments.as_slice() {
                [argument] => parse_unsigned_decimal(argument)
                    .is_some_and(|number| (min..=max).contains(&number)),
                _ => false,
            },
            Self::NonNegativeTimeOrNone => match arguments.as_slice() {
                [argument] => argument == "none" || parse_time_seconds(argument).is_some(),
                _ => false,
            },
            Self::OctalMask => match arguments.as_slice() {
                [argument] => parse_octal_mask(argument).is_some(),
                _ => false,
            },
            Self::IpQos => {
                (1..=2).contains(&arguments.len())
                    && arguments.iter().all(|argument| accepts_ipqos(argument))
            }
            Self::AllowedValues(values) => match arguments.as_slice() {
                [argument] => values
                    .iter()
                    .any(|value| argument.eq_ignore_ascii_case(value)),
                _ => false,
            },
        }
    }
}

fn parse_value_arguments(value: &str) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut started = false;

    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            started = true;
            continue;
        }

        match character {
            '\\' if quoted => {
                escaped = true;
                started = true;
            }
            '"' => {
                quoted = !quoted;
                started = true;
            }
            character if character.is_whitespace() && !quoted => {
                if started {
                    arguments.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(character);
                started = true;
            }
        }
    }

    if quoted || escaped {
        return None;
    }
    if started {
        arguments.push(current);
    }
    Some(arguments)
}

fn parse_unsigned_decimal(value: &str) -> Option<u64> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse_time_seconds(value: &str) -> Option<u64> {
    const MAX_SECONDS: f64 = i32::MAX as f64;

    if value.is_empty() || !value.is_ascii() {
        return None;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    let mut total = 0.0;
    let mut seen_seconds = false;

    while index < bytes.len() {
        let start = index;
        let mut digits = 0;
        let mut dots = 0;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
            if bytes[index] == b'.' {
                dots += 1;
            } else {
                digits += 1;
            }
            index += 1;
        }
        if digits == 0 || dots > 1 {
            return None;
        }

        let number_text = &value[start..index];
        if dots == 1
            && !number_text
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let number = number_text.parse::<f64>().ok()?;

        let unit = bytes.get(index).copied();
        let multiplier = match unit {
            None => 1.0,
            Some(b's' | b'S') => 1.0,
            Some(b'm' | b'M') => 60.0,
            Some(b'h' | b'H') => 60.0 * 60.0,
            Some(b'd' | b'D') => 24.0 * 60.0 * 60.0,
            Some(b'w' | b'W') => 7.0 * 24.0 * 60.0 * 60.0,
            _ => return None,
        };

        if dots == 1 && multiplier != 1.0 {
            return None;
        }
        if multiplier == 1.0 {
            if seen_seconds {
                return None;
            }
            seen_seconds = true;
        }

        total += number * multiplier;
        if !total.is_finite() || total > MAX_SECONDS {
            return None;
        }

        if unit.is_some() {
            index += 1;
        }
    }

    Some(total as u64)
}

fn parse_octal_mask(value: &str) -> Option<u16> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return None;
    }
    let mask = u16::from_str_radix(digits, 8).ok()?;
    (mask <= 0o777).then_some(mask)
}

const IPQOS_NAMES: &[&str] = &[
    "none",
    "af11",
    "af12",
    "af13",
    "af21",
    "af22",
    "af23",
    "af31",
    "af32",
    "af33",
    "af41",
    "af42",
    "af43",
    "cs0",
    "cs1",
    "cs2",
    "cs3",
    "cs4",
    "cs5",
    "cs6",
    "cs7",
    "ef",
    "le",
    "va",
    // OpenSSH still accepts these deprecated aliases and falls back to the
    // operating-system default. A future rule may warn about them.
    "lowdelay",
    "throughput",
    "reliability",
];

fn accepts_ipqos(value: &str) -> bool {
    IPQOS_NAMES
        .iter()
        .any(|name| value.eq_ignore_ascii_case(name))
        || parse_unsigned_decimal(value).is_some_and(|number| number <= 255)
}

struct DirectiveValueSpec {
    directive: &'static str,
    constraint: ValueConstraint,
    expected: &'static str,
    hint: &'static str,
}

const DIRECTIVE_VALUE_SPECS: &[DirectiveValueSpec] = &[
    DirectiveValueSpec {
        directive: "Port",
        constraint: ValueConstraint::UnsignedIntegerRange {
            min: 1,
            max: 65_535,
        },
        expected: "an integer from 1 to 65535",
        hint: "use a port number from 1 to 65535",
    },
    DirectiveValueSpec {
        directive: "ConnectionAttempts",
        constraint: ValueConstraint::UnsignedIntegerRange {
            min: 1,
            max: i32::MAX as u64,
        },
        expected: "an integer from 1 to 2147483647",
        hint: "use at least 1 connection attempt",
    },
    DirectiveValueSpec {
        directive: "ConnectTimeout",
        constraint: ValueConstraint::NonNegativeTimeOrNone,
        expected: "a non-negative time value or none",
        hint: "use seconds, a duration such as 1m30s, or none",
    },
    DirectiveValueSpec {
        directive: "NumberOfPasswordPrompts",
        constraint: ValueConstraint::UnsignedIntegerRange {
            min: 0,
            max: i32::MAX as u64,
        },
        expected: "an integer from 0 to 2147483647",
        hint: "use a non-negative integer no greater than 2147483647",
    },
    DirectiveValueSpec {
        directive: "ServerAliveInterval",
        constraint: ValueConstraint::NonNegativeTimeOrNone,
        expected: "a non-negative time value or none",
        hint: "use seconds, a duration such as 1m30s, or none",
    },
    DirectiveValueSpec {
        directive: "ServerAliveCountMax",
        constraint: ValueConstraint::UnsignedIntegerRange {
            min: 0,
            max: i32::MAX as u64,
        },
        expected: "an integer from 0 to 2147483647",
        hint: "use a non-negative integer no greater than 2147483647",
    },
    DirectiveValueSpec {
        directive: "CanonicalizeMaxDots",
        constraint: ValueConstraint::UnsignedIntegerRange {
            min: 0,
            max: i32::MAX as u64,
        },
        expected: "an integer from 0 to 2147483647",
        hint: "use a non-negative integer no greater than 2147483647",
    },
    DirectiveValueSpec {
        directive: "StreamLocalBindMask",
        constraint: ValueConstraint::OctalMask,
        expected: "an octal mask from 0000 to 0777",
        hint: "use a complete octal value from 0000 to 0777, for example 0177",
    },
    DirectiveValueSpec {
        directive: "IPQoS",
        constraint: ValueConstraint::IpQos,
        expected: "one or two DSCP names or numbers from 0 to 255",
        hint: "use a DSCP name such as af21, a number from 0 to 255, or none",
    },
    DirectiveValueSpec {
        directive: "AddressFamily",
        constraint: ValueConstraint::AllowedValues(&["any", "inet", "inet6"]),
        expected: "one of: any, inet, inet6",
        hint: "use any, inet, or inet6",
    },
    DirectiveValueSpec {
        directive: "RequestTTY",
        constraint: ValueConstraint::AllowedValues(&[
            "true", "false", "yes", "no", "force", "auto",
        ]),
        expected: "one of: true, false, yes, no, force, auto",
        hint: "use yes, no, force, or auto; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "SessionType",
        constraint: ValueConstraint::AllowedValues(&["none", "subsystem", "default"]),
        expected: "one of: none, subsystem, default",
        hint: "use none, subsystem, or default",
    },
    DirectiveValueSpec {
        directive: "ControlMaster",
        constraint: ValueConstraint::AllowedValues(&[
            "true", "false", "yes", "no", "auto", "ask", "autoask",
        ]),
        expected: "one of: true, false, yes, no, auto, ask, autoask",
        hint: "use yes, no, auto, ask, or autoask; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "CanonicalizeHostname",
        constraint: ValueConstraint::AllowedValues(&["true", "false", "yes", "no", "always"]),
        expected: "one of: true, false, yes, no, always",
        hint: "use yes, no, or always; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "StrictHostKeyChecking",
        constraint: ValueConstraint::AllowedValues(&[
            "true",
            "false",
            "yes",
            "no",
            "ask",
            "off",
            "accept-new",
        ]),
        expected: "one of: true, false, yes, no, ask, off, accept-new",
        hint: "use yes, ask, accept-new, no, or off; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "UpdateHostKeys",
        constraint: ValueConstraint::AllowedValues(&["true", "false", "yes", "no", "ask"]),
        expected: "one of: true, false, yes, no, ask",
        hint: "use yes, no, or ask; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "VerifyHostKeyDNS",
        constraint: ValueConstraint::AllowedValues(&["true", "false", "yes", "no", "ask"]),
        expected: "one of: true, false, yes, no, ask",
        hint: "use yes, no, or ask; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "Tunnel",
        constraint: ValueConstraint::AllowedValues(&[
            "ethernet",
            "point-to-point",
            "true",
            "false",
            "yes",
            "no",
        ]),
        expected: "one of: ethernet, point-to-point, true, false, yes, no",
        hint: "use ethernet, point-to-point, yes, or no; true and false are also accepted",
    },
    DirectiveValueSpec {
        directive: "LogLevel",
        constraint: ValueConstraint::AllowedValues(&[
            "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3",
        ]),
        expected: "one of: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, DEBUG3",
        hint: "use a log level from QUIET through DEBUG3",
    },
    DirectiveValueSpec {
        directive: "SyslogFacility",
        constraint: ValueConstraint::AllowedValues(&[
            "DAEMON", "USER", "AUTH", "AUTHPRIV", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4",
            "LOCAL5", "LOCAL6", "LOCAL7",
        ]),
        expected: "one of: DAEMON, USER, AUTH, AUTHPRIV, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7",
        hint: "use DAEMON, USER, AUTH, AUTHPRIV, or LOCAL0 through LOCAL7",
    },
    DirectiveValueSpec {
        directive: "PubkeyAuthentication",
        constraint: ValueConstraint::AllowedValues(&[
            "true",
            "false",
            "yes",
            "no",
            "unbound",
            "host-bound",
        ]),
        expected: "one of: true, false, yes, no, unbound, host-bound",
        hint: "use yes, no, unbound, or host-bound; true and false are also accepted",
    },
];

/// Errors when a directive has a value OpenSSH does not accept.
pub struct InvalidDirectiveValue;

impl Rule for InvalidDirectiveValue {
    fn name(&self) -> &'static str {
        "invalid-directive-value"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_invalid_value_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_invalid_value_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } => {
                let Some(spec) = DIRECTIVE_VALUE_SPECS
                    .iter()
                    .find(|spec| key.eq_ignore_ascii_case(spec.directive))
                else {
                    continue;
                };
                if spec.constraint.accepts(value) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        Severity::Error,
                        "invalid-directive-value",
                        "INVALID_VALUE",
                        format!(
                            "invalid value '{}' for {}; expected {}",
                            value, spec.directive, spec.expected
                        ),
                        span.clone(),
                    )
                    .with_hint(spec.hint),
                );
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_invalid_value_findings(items, findings);
            }
            _ => {}
        }
    }
}
