//! Compatibility exports for the pre-v1 `rules::basic` module path.

pub use super::implementations::{
    DeprecatedWeakAlgorithms, DuplicateDirectives, DuplicateHost, IdentityFileExists,
    InsecureOption, InvalidDirectiveValue, UnsafeControlPath, WildcardHostOrder,
};
