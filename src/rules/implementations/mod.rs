//! Built-in rule implementations.
//!
//! Keep one public rule type per file. To add a rule, copy the closest
//! implementation, adjust its tests, export it here, and register it in
//! `rules::run_all` and, when it is filesystem-independent, `run_portable`.

mod certificate_file_exists;
mod control_persist_requires_master;
mod deprecated_option;
mod deprecated_weak_algorithms;
mod duplicate_directives;
mod duplicate_host;
mod explicit_path;
mod identity_file_exists;
mod insecure_option;
mod invalid_directive_value;
mod invalid_match_condition;
mod invalid_percent_token;
mod invalid_syntax;
mod local_command_enabled;
mod negated_only_host;
mod proxy_command_jump_conflict;
mod revoked_host_keys_readable;
mod unknown_directive;
mod unsafe_control_path;
mod update_hostkeys_control_persist;
mod value_arguments;
mod wildcard_host_order;

#[cfg(test)]
mod tests;

pub use certificate_file_exists::CertificateFileExists;
pub use control_persist_requires_master::ControlPersistRequiresMaster;
pub use deprecated_option::DeprecatedOption;
pub use deprecated_weak_algorithms::DeprecatedWeakAlgorithms;
pub use duplicate_directives::DuplicateDirectives;
pub use duplicate_host::DuplicateHost;
pub use identity_file_exists::IdentityFileExists;
pub use insecure_option::InsecureOption;
pub use invalid_directive_value::InvalidDirectiveValue;
pub use invalid_match_condition::InvalidMatchCondition;
pub use invalid_percent_token::InvalidPercentToken;
pub use invalid_syntax::InvalidSyntax;
pub use local_command_enabled::LocalCommandEnabled;
pub use negated_only_host::NegatedOnlyHost;
pub use proxy_command_jump_conflict::ProxyCommandJumpConflict;
pub use revoked_host_keys_readable::RevokedHostKeysReadable;
pub use unknown_directive::UnknownDirective;
pub use unsafe_control_path::UnsafeControlPath;
pub use update_hostkeys_control_persist::UpdateHostKeysControlPersist;
pub use wildcard_host_order::WildcardHostOrder;
