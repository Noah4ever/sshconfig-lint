//! Compatibility exports for the pre-v1 `rules::basic` module path.

pub use super::implementations::{
    CertificateFileExists, ControlPersistRequiresMaster, DeprecatedOption,
    DeprecatedWeakAlgorithms, DuplicateDirectives, DuplicateHost, IdentityFileExists,
    InsecureOption, InvalidDirectiveValue, InvalidMatchCondition, InvalidPercentToken,
    InvalidSyntax, LocalCommandEnabled, NegatedOnlyHost, ProxyCommandJumpConflict,
    RevokedHostKeysReadable, UnknownDirective, UnsafeControlPath, UpdateHostKeysControlPersist,
    WildcardHostOrder,
};
