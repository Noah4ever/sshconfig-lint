//! Compatibility exports for the pre-v1 `rules::basic` module path.

pub use super::implementations::{
    CertificateFileExists, DeprecatedWeakAlgorithms, DuplicateDirectives, DuplicateHost,
    IdentityFileExists, InsecureOption, InvalidDirectiveValue, InvalidPercentToken,
    LocalCommandEnabled, NegatedOnlyHost, ProxyCommandJumpConflict, RevokedHostKeysReadable,
    UnsafeControlPath, WildcardHostOrder,
};
