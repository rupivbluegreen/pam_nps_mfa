//! pam.d module-argument parsing (IMPLEMENTATION_SPEC.md §7).
//!
//! Policy stays in the config file; the module line only carries:
//!
//! ```text
//! config=<path>     override the config file path
//! try_first_pass    use a password from an earlier module if present, else prompt
//! use_first_pass    use a password from an earlier module, do not prompt; fail if absent
//! debug             enable metadata debug logging
//! ```
//!
//! Module options are operator-supplied (root wrote the pam.d line), not
//! network input, so an unknown option is ignored — recorded for a debug log
//! line (phase 7 audit) — rather than failing the whole stack closed. This is
//! the PAM ecosystem convention and is deliberately different from the config
//! *file* parser, which rejects unknown keys (CLAUDE.md rule 13).

use std::path::PathBuf;

/// Default configuration path (IMPLEMENTATION_SPEC.md §6).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/pam_nps/pam_nps.conf";

/// Parsed module options. No secret material lives here, so `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Config file path (`config=<path>`, default [`DEFAULT_CONFIG_PATH`]).
    pub config_path: PathBuf,
    /// Use an earlier module's password if present, else prompt.
    pub try_first_pass: bool,
    /// Use an earlier module's password; never prompt; fail if absent.
    pub use_first_pass: bool,
    /// Metadata-only debug logging (never credential bytes — rule 3).
    pub debug: bool,
    /// Unrecognized options, kept only so the phase-7 debug log can name them.
    pub unknown: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
            try_first_pass: false,
            use_first_pass: false,
            debug: false,
            unknown: Vec::new(),
        }
    }
}

/// Parse the pam.d argument list (already converted to Rust strings by the
/// FFI boundary). Never fails: unknown options are collected, not fatal.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Options {
    let mut options = Options::default();
    for arg in args {
        let arg = arg.as_ref();
        if let Some(path) = arg.strip_prefix("config=") {
            if path.is_empty() {
                // `config=` with no path: keep the default, note the oddity.
                options.unknown.push(arg.to_owned());
            } else {
                options.config_path = PathBuf::from(path);
            }
            continue;
        }
        match arg {
            "try_first_pass" => options.try_first_pass = true,
            "use_first_pass" => options.use_first_pass = true,
            "debug" => options.debug = true,
            other => options.unknown.push(other.to_owned()),
        }
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let o = parse::<&str>(&[]);
        assert_eq!(o.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert!(!o.try_first_pass);
        assert!(!o.use_first_pass);
        assert!(!o.debug);
        assert!(o.unknown.is_empty());
    }

    #[test]
    fn all_known_options() {
        let o = parse(&[
            "config=/etc/other/pam_nps.conf",
            "try_first_pass",
            "use_first_pass",
            "debug",
        ]);
        assert_eq!(o.config_path, PathBuf::from("/etc/other/pam_nps.conf"));
        assert!(o.try_first_pass);
        assert!(o.use_first_pass);
        assert!(o.debug);
        assert!(o.unknown.is_empty());
    }

    #[test]
    fn unknown_options_are_ignored_not_fatal() {
        let o = parse(&["nullok", "config=", "bogus=1"]);
        assert_eq!(o.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(o.unknown, vec!["nullok", "config=", "bogus=1"]);
    }
}
