//! Built-in rule implementations.
//!
//! Keep one public rule type per file. To add a rule, copy the closest
//! implementation, adjust its tests, export it here, and register it in
//! `rules::run_all` and, when it is filesystem-independent, `run_portable`.

mod deprecated_weak_algorithms;
mod duplicate_directives;
mod duplicate_host;
mod identity_file_exists;
mod insecure_option;
mod invalid_directive_value;
mod unsafe_control_path;
mod wildcard_host_order;

#[cfg(test)]
mod tests;

pub use deprecated_weak_algorithms::DeprecatedWeakAlgorithms;
pub use duplicate_directives::DuplicateDirectives;
pub use duplicate_host::DuplicateHost;
pub use identity_file_exists::IdentityFileExists;
pub use insecure_option::InsecureOption;
pub use invalid_directive_value::InvalidDirectiveValue;
pub use unsafe_control_path::UnsafeControlPath;
pub use wildcard_host_order::WildcardHostOrder;
