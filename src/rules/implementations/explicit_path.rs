use std::fs::File;
use std::path::PathBuf;

pub(super) fn resolve_explicit_path(value: &str) -> Option<PathBuf> {
    if value.contains('%') || value.contains("${") {
        return None;
    }

    if value == "~" {
        return dirs::home_dir();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return dirs::home_dir().map(|home| home.join(rest));
    }
    if value.starts_with('~') {
        return None;
    }

    Some(PathBuf::from(value))
}

pub(super) fn is_readable_regular_file(path: &PathBuf) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.is_file()) && File::open(path).is_ok()
}
