#![forbid(unsafe_code)]
//! Configuration parsing and permission checks for `pam_nps_mfa` (phase 4).
//!
//! Two jobs, both from IMPLEMENTATION_SPEC.md §6 (with amendment A1):
//!
//! 1. **TOCTOU-safe secure file loading.** The config file and every per-server
//!    secret file is opened with `O_NOFOLLOW` (so a symlink as the final path
//!    component makes the open fail — defeats a symlink swap), then the
//!    *resulting descriptor* is `fstat`ed via [`std::fs::File::metadata`] (which
//!    stats the open fd, not the path — no re-stat, no TOCTOU window). The file
//!    must be a regular file, owned by uid 0, with no group/other permission
//!    bits (`mode & 0o077 == 0`). Any failure is a hard error and the contents
//!    are never read. See [`load`] and [`validate_permissions`].
//!
//! 2. **Fail-closed parsing.** A line-oriented `key value` grammar. A duplicate
//!    scalar key, an unknown key, a malformed value, or a missing required key
//!    (at least one `server`, and `protocol`) is an error. Nothing is guessed.
//!    See [`parse`].
//!
//! Security posture (CLAUDE.md hard rules; SECURITY_DESIGN.md §7/§8):
//! - Fail closed (rules 1, 12): a permissive or swappable config/secret file is
//!   a *hard* failure ([`ConfigError::InsecurePermissions`]) that refuses to run
//!   — never a warning. The PAM layer maps every [`ConfigError`] to
//!   `PAM_AUTHINFO_UNAVAIL` and logs a critical audit event.
//! - No secret in `Debug`/logs (rule 3): each server's shared secret lives in a
//!   [`secrets::SecretString`] (redacting `Debug`, zeroized on drop). The error
//!   types carry only key names, line numbers, file paths, and OS error kinds —
//!   never file contents.
//! - No invented keys (rule 13): the accepted key set is exactly the schema in
//!   IMPLEMENTATION_SPEC.md §6 plus the owner-approved `probe_timeout`
//!   (SPEC_AMENDMENTS.md A1). Any other key is rejected.
//! - No `unsafe`: the crate forbids it. `libc` is used only for the
//!   `O_NOFOLLOW` integer constant; the open/fstat/read is 100% safe std API
//!   (`OpenOptionsExt::custom_flags`, `File::metadata`, `MetadataExt`).

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use secrets::SecretString;

/// The uid a production config/secret file must be owned by: root.
const ROOT_UID: u32 = 0;

/// Default per-server transport probe window (SPEC_AMENDMENTS.md A1).
pub const DEFAULT_PROBE_TIMEOUT: u32 = 5;
/// Default per-server MFA-completion wait. IMPLEMENTATION_SPEC.md §3 and
/// SECURITY_DESIGN.md §12: "Microsoft recommends at least sixty seconds, and
/// the module defaults accordingly" while staying under a sane LoginGraceTime.
pub const DEFAULT_TIMEOUT: u32 = 60;
/// Default identical-packet retransmits per server. Mirrors the
/// IMPLEMENTATION_SPEC.md §6 sample (`retries 1`); "the retry count is small".
pub const DEFAULT_RETRIES: u32 = 1;

// ===========================================================================
// Typed configuration
// ===========================================================================

/// Credential protocol, fixed for the life of the process (CLAUDE.md rule 5).
/// There is no default and no negotiation: an absent or unknown `protocol` is
/// an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// MSCHAPv2 (the primary target).
    Mschapv2,
    /// PAP.
    Pap,
}

/// Where audit records go (IMPLEMENTATION_SPEC.md §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBackend {
    /// Native auditd only.
    Auditd,
    /// syslog only.
    Syslog,
    /// Both backends.
    Both,
}

/// One RADIUS server: its `ip:port` and the shared secret loaded from that
/// server's secret file. Ordered relative to the other servers.
///
/// `Debug` is safe to derive here: the only secret field is a
/// [`secrets::SecretString`], whose own `Debug` redacts (CLAUDE.md rule 3).
#[derive(Debug)]
pub struct Server {
    /// The server socket address (`ip:port`).
    pub addr: SocketAddr,
    /// The RADIUS shared secret for this server, zeroized on drop.
    pub secret: SecretString,
}

/// A fully validated configuration with every secret loaded.
///
/// `Debug` is safe: the only secret material is inside [`Server::secret`],
/// which redacts itself.
#[derive(Debug)]
pub struct Config {
    /// One or more servers, tried in the order listed.
    pub servers: Vec<Server>,
    /// The fixed credential protocol.
    pub protocol: Protocol,
    /// Per-server MFA-completion wait, seconds.
    pub timeout: u32,
    /// Per-server transport probe window, seconds (A1).
    pub probe_timeout: u32,
    /// Identical-packet retransmits per server.
    pub retries: u32,
    /// NAS-Identifier (type 32) to send, if configured.
    pub nas_identifier: Option<String>,
    /// NAS-IP-Address (type 4) to send, if configured.
    pub nas_ip: Option<Ipv4Addr>,
    /// Client socket bind address, if configured.
    pub source_ip: Option<Ipv4Addr>,
    /// Strict mode: reject responses lacking a Message-Authenticator. Default
    /// `true` (SECURITY_DESIGN.md §5).
    pub require_message_authenticator: bool,
    /// Audit backend selection.
    pub audit: AuditBackend,
    /// Metadata-only debug logging. Never enables credential-byte logging.
    pub debug: bool,
}

// ===========================================================================
// Parsed (pre-secret-load) configuration
// ===========================================================================

/// A parsed `server` entry before its secret file is opened. The path is not
/// secret; the secret it points at is loaded (with permission checks) later.
///
/// `PartialEq`/`Eq` are safe here (no secret material — unlike [`Config`],
/// which holds a [`secrets::SecretString`] and deliberately has neither).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServer {
    /// The server socket address (`ip:port`).
    pub addr: SocketAddr,
    /// Path to this server's secret file.
    pub secret_path: PathBuf,
}

/// The result of [`parse`]: a validated configuration whose secret files have
/// **not** yet been opened. This is the seam the parser tests exercise, so the
/// grammar can be checked on already-in-memory text with no filesystem or
/// permission dependency.
///
/// `PartialEq`/`Eq` are safe here: this pre-secret-load form carries no secret
/// material (secret files are only opened later, in [`Config`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    /// One or more parsed servers, in order.
    pub servers: Vec<ParsedServer>,
    /// The fixed credential protocol.
    pub protocol: Protocol,
    /// Per-server MFA-completion wait, seconds.
    pub timeout: u32,
    /// Per-server transport probe window, seconds (A1).
    pub probe_timeout: u32,
    /// Identical-packet retransmits per server.
    pub retries: u32,
    /// NAS-Identifier to send, if configured.
    pub nas_identifier: Option<String>,
    /// NAS-IP-Address to send, if configured.
    pub nas_ip: Option<Ipv4Addr>,
    /// Client socket bind address, if configured.
    pub source_ip: Option<Ipv4Addr>,
    /// Strict Message-Authenticator mode. Default `true`.
    pub require_message_authenticator: bool,
    /// Audit backend selection.
    pub audit: AuditBackend,
    /// Metadata-only debug logging.
    pub debug: bool,
}

// ===========================================================================
// Errors
// ===========================================================================

/// Why a file failed its type/ownership/mode check. Every variant is a hard
/// failure (CLAUDE.md rule 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermIssue {
    /// Not a regular file (directory, fifo, socket, device, …).
    NotRegularFile,
    /// Owner uid is not the required uid (0 in production).
    WrongOwner {
        /// The uid actually found on the file.
        found: u32,
        /// The uid the file was required to be owned by.
        expected: u32,
    },
    /// Group or other permission bits are set (`mode & 0o077 != 0`), i.e. the
    /// file is readable/writable/executable by someone other than its owner.
    GroupOrOtherAccessible {
        /// The full st_mode as returned by `fstat`.
        mode: u32,
    },
}

impl std::fmt::Display for PermIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::WrongOwner { found, expected } => {
                write!(f, "wrong owner: found uid {found}, require uid {expected}")
            }
            Self::GroupOrOtherAccessible { mode } => {
                write!(f, "group/other-accessible (mode {mode:#o}); require mode & 0o077 == 0")
            }
        }
    }
}

/// A line-level parse/validation failure. Fail closed (CLAUDE.md rule 1).
///
/// Carries only key names, line numbers, and required-key names — never a
/// value, since including raw value text is unnecessary and keeps the error
/// safe to surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A key not in the schema (IMPLEMENTATION_SPEC.md §6 + A1). Rule 13.
    UnknownKey {
        /// 1-based line number.
        line: usize,
        /// The offending key token.
        key: String,
    },
    /// A scalar key appeared more than once (ambiguous → deny).
    DuplicateKey {
        /// 1-based line number of the second occurrence.
        line: usize,
        /// The duplicated key.
        key: String,
    },
    /// The value could not be parsed (bad int, bad IP, bad enum, wrong number
    /// of value tokens).
    MalformedValue {
        /// 1-based line number.
        line: usize,
        /// The key whose value was malformed.
        key: String,
    },
    /// A required key was missing (`"server"` or `"protocol"`).
    MissingRequired {
        /// The missing required key.
        key: &'static str,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey { line, key } => {
                write!(f, "line {line}: unknown key '{key}'")
            }
            Self::DuplicateKey { line, key } => {
                write!(f, "line {line}: duplicate key '{key}'")
            }
            Self::MalformedValue { line, key } => {
                write!(f, "line {line}: malformed value for key '{key}'")
            }
            Self::MissingRequired { key } => {
                write!(f, "missing required key '{key}'")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Any reason the configuration could not be loaded. Every variant denies and
/// is mapped by the PAM layer to `PAM_AUTHINFO_UNAVAIL` with a critical audit
/// event (IMPLEMENTATION_SPEC.md §7).
#[derive(Debug)]
pub enum ConfigError {
    /// Opening the file failed. This includes `O_NOFOLLOW` rejecting a
    /// final-component symlink. Contents were never read.
    Open {
        /// The path that failed to open.
        path: PathBuf,
        /// The OS error.
        source: std::io::Error,
    },
    /// `fstat` on, or reading from, the already-opened descriptor failed.
    Read {
        /// The path being read.
        path: PathBuf,
        /// The OS error.
        source: std::io::Error,
    },
    /// The file failed its type/ownership/mode check before its contents were
    /// trusted. Hard failure (CLAUDE.md rule 12).
    InsecurePermissions {
        /// The offending path.
        path: PathBuf,
        /// What specifically was wrong.
        issue: PermIssue,
    },
    /// The config text failed to parse/validate. Fail closed.
    Parse(ParseError),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(f, "failed to open '{}': {source}", path.display())
            }
            Self::Read { path, source } => {
                write!(f, "failed to read '{}': {source}", path.display())
            }
            Self::InsecurePermissions { path, issue } => {
                write!(f, "insecure permissions on '{}': {issue}", path.display())
            }
            Self::Parse(e) => write!(f, "config parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Read { source, .. } => Some(source),
            Self::Parse(e) => Some(e),
            Self::InsecurePermissions { .. } => None,
        }
    }
}

impl From<ParseError> for ConfigError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

// ===========================================================================
// Permission check (the injectable seam)
// ===========================================================================

/// Validate the type, ownership, and mode of an already-`fstat`ed descriptor.
///
/// This is pure logic over a [`std::fs::Metadata`] and takes the required owner
/// uid as a parameter, which is what makes the permission checks unit-testable
/// by a **non-root** test: production calls this (via [`load`]) with
/// `expected_uid == 0`, while a test can create a file it owns and pass its own
/// uid to exercise the type/mode logic, or pass `0` to exercise the
/// wrong-owner path. The three checks run in this order so that a directory
/// reports [`PermIssue::NotRegularFile`] rather than an owner/mode complaint.
///
/// # Errors
/// Returns a [`PermIssue`] if the metadata describes a non-regular file, a file
/// not owned by `expected_uid`, or a file with any group/other permission bit.
pub fn validate_permissions(
    meta: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), PermIssue> {
    if !meta.is_file() {
        return Err(PermIssue::NotRegularFile);
    }
    let uid = meta.uid();
    if uid != expected_uid {
        return Err(PermIssue::WrongOwner {
            found: uid,
            expected: expected_uid,
        });
    }
    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(PermIssue::GroupOrOtherAccessible { mode });
    }
    Ok(())
}

// ===========================================================================
// Secure open + read
// ===========================================================================

/// Open `path` with `O_NOFOLLOW`, `fstat` the resulting descriptor, and
/// enforce the type/ownership/mode contract, returning the open file and its
/// metadata. No content is read here.
fn open_secure(path: &Path, expected_uid: u32) -> Result<(File, std::fs::Metadata), ConfigError> {
    // O_NOFOLLOW: if the final path component is a symlink, the open fails
    // (ELOOP) — this defeats a symlink swap of the config/secret path.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ConfigError::Open {
            path: path.to_path_buf(),
            source,
        })?;

    // fstat the *open descriptor*, not the path (File::metadata → fstat(fd)).
    // No re-stat of the name, so no TOCTOU window between check and use.
    let meta = file.metadata().map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    validate_permissions(&meta, expected_uid).map_err(|issue| {
        ConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            issue,
        }
    })?;

    Ok((file, meta))
}

/// Read the config text from an already-validated descriptor. The config text
/// itself is not secret (secrets live in separate files), so a plain `String`
/// is fine.
fn read_config_text(file: &mut File, path: &Path) -> Result<String, ConfigError> {
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(text)
}

/// Read a secret file's content from an already-validated descriptor into a
/// [`SecretString`], stripping a single trailing newline.
///
/// The bytes are read into a zeroizing scratch buffer (sized from the fstat
/// length so the read does not reallocate and leave an un-zeroized copy), then
/// validated as UTF-8 and copied into the `SecretString`; the scratch buffer is
/// wiped on drop.
fn read_secret(file: &mut File, meta: &std::fs::Metadata, path: &Path) -> Result<SecretString, ConfigError> {
    let hint = usize::try_from(meta.len()).unwrap_or(0);
    // Zeroizing scratch: on drop the raw secret bytes are overwritten.
    let mut scratch = zeroize::Zeroizing::new(Vec::<u8>::with_capacity(hint));
    file.read_to_end(&mut scratch)
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

    // Strip exactly one trailing newline (IMPLEMENTATION_SPEC.md §6).
    let bytes: &[u8] = match scratch.split_last() {
        Some((b'\n', rest)) => rest,
        _ => &scratch[..],
    };

    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "secret file is not valid UTF-8",
        ),
    })?;

    Ok(SecretString::from_text(text))
}

// ===========================================================================
// Load (production + testable seam)
// ===========================================================================

/// Load and fully validate the configuration at `path`, requiring the config
/// file and every per-server secret file to be a root-owned (uid 0) regular
/// file with no group/other permission bits.
///
/// This is the production entry point. See IMPLEMENTATION_SPEC.md §6.
///
/// # Errors
/// Returns a [`ConfigError`] on any open/permission/read/parse failure. Every
/// variant denies (fail closed); nothing is read from a file that fails its
/// permission check.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    load_with_expected_uid(path, ROOT_UID)
}

/// Same as [`load`] but with the required owner uid injected.
///
/// This exists **only** so the full open → `fstat` → validate → read → parse →
/// secret-load pipeline can be exercised by a non-root test (which passes its
/// own uid). Production code must call [`load`], which pins `expected_uid` to
/// `0`. It is `#[doc(hidden)]` for that reason.
///
/// # Errors
/// As [`load`].
#[doc(hidden)]
pub fn load_with_expected_uid(path: &Path, expected_uid: u32) -> Result<Config, ConfigError> {
    let (mut file, _meta) = open_secure(path, expected_uid)?;
    let text = read_config_text(&mut file, path)?;
    let parsed = parse(&text)?;
    resolve(parsed, expected_uid)
}

/// Open each parsed server's secret file (same permission contract) and build
/// the final [`Config`].
fn resolve(parsed: ParsedConfig, expected_uid: u32) -> Result<Config, ConfigError> {
    let mut servers = Vec::with_capacity(parsed.servers.len());
    for ps in parsed.servers {
        let (mut file, meta) = open_secure(&ps.secret_path, expected_uid)?;
        let secret = read_secret(&mut file, &meta, &ps.secret_path)?;
        servers.push(Server {
            addr: ps.addr,
            secret,
        });
    }
    Ok(Config {
        servers,
        protocol: parsed.protocol,
        timeout: parsed.timeout,
        probe_timeout: parsed.probe_timeout,
        retries: parsed.retries,
        nas_identifier: parsed.nas_identifier,
        nas_ip: parsed.nas_ip,
        source_ip: parsed.source_ip,
        require_message_authenticator: parsed.require_message_authenticator,
        audit: parsed.audit,
        debug: parsed.debug,
    })
}

// ===========================================================================
// Parser
// ===========================================================================

/// Parse configuration text into a [`ParsedConfig`] (secrets not yet loaded).
///
/// The grammar is line-oriented `key value`; `#` starts a comment; blank lines
/// are ignored. Exactly the schema in IMPLEMENTATION_SPEC.md §6 plus the
/// owner-approved `probe_timeout` (A1) is accepted.
///
/// # Errors
/// Returns a [`ParseError`] on a duplicate scalar key, an unknown key, a
/// malformed value (bad int/IP/enum or wrong token count), or a missing
/// required key (no `server`, or no `protocol`). Fail closed (CLAUDE.md rule 1).
pub fn parse(text: &str) -> Result<ParsedConfig, ParseError> {
    let mut servers: Vec<ParsedServer> = Vec::new();
    let mut protocol: Option<Protocol> = None;
    let mut timeout: Option<u32> = None;
    let mut probe_timeout: Option<u32> = None;
    let mut retries: Option<u32> = None;
    let mut nas_identifier: Option<String> = None;
    let mut nas_ip: Option<Ipv4Addr> = None;
    let mut source_ip: Option<Ipv4Addr> = None;
    let mut require_ma: Option<bool> = None;
    let mut audit: Option<AuditBackend> = None;
    let mut debug: Option<bool> = None;

    for (idx, raw_line) in text.lines().enumerate() {
        let line = idx + 1;

        // A '#' anywhere starts a comment (supports inline comments, as used in
        // the IMPLEMENTATION_SPEC.md §6 sample).
        let content = match raw_line.find('#') {
            Some(i) => &raw_line[..i],
            None => raw_line,
        };
        let content = content.trim();
        if content.is_empty() {
            continue;
        }

        let mut tokens = content.split_whitespace();
        let key = match tokens.next() {
            Some(k) => k,
            None => continue, // unreachable: content is non-empty and trimmed
        };
        let rest: Vec<&str> = tokens.collect();

        match key {
            "server" => {
                // `server <ip:port> <secret_path>` — exactly two value tokens.
                if rest.len() != 2 {
                    return Err(malformed(line, key));
                }
                let addr = rest[0]
                    .parse::<SocketAddr>()
                    .map_err(|_| malformed(line, key))?;
                servers.push(ParsedServer {
                    addr,
                    secret_path: PathBuf::from(rest[1]),
                });
            }
            "protocol" => {
                let v = single(&rest, line, key)?;
                set_once(&mut protocol, line, key)?;
                protocol = Some(match v {
                    "mschapv2" => Protocol::Mschapv2,
                    "pap" => Protocol::Pap,
                    _ => return Err(malformed(line, key)),
                });
            }
            "timeout" => {
                let v = single(&rest, line, key)?;
                set_once(&mut timeout, line, key)?;
                timeout = Some(parse_u32(v, line, key)?);
            }
            "probe_timeout" => {
                let v = single(&rest, line, key)?;
                set_once(&mut probe_timeout, line, key)?;
                probe_timeout = Some(parse_u32(v, line, key)?);
            }
            "retries" => {
                let v = single(&rest, line, key)?;
                set_once(&mut retries, line, key)?;
                retries = Some(parse_u32(v, line, key)?);
            }
            "nas_identifier" => {
                let v = single(&rest, line, key)?;
                set_once(&mut nas_identifier, line, key)?;
                nas_identifier = Some(v.to_owned());
            }
            "nas_ip" => {
                let v = single(&rest, line, key)?;
                set_once(&mut nas_ip, line, key)?;
                nas_ip = Some(v.parse::<Ipv4Addr>().map_err(|_| malformed(line, key))?);
            }
            "source_ip" => {
                let v = single(&rest, line, key)?;
                set_once(&mut source_ip, line, key)?;
                source_ip = Some(v.parse::<Ipv4Addr>().map_err(|_| malformed(line, key))?);
            }
            "require_message_authenticator" => {
                let v = single(&rest, line, key)?;
                set_once(&mut require_ma, line, key)?;
                require_ma = Some(parse_bool(v, line, key)?);
            }
            "audit" => {
                let v = single(&rest, line, key)?;
                set_once(&mut audit, line, key)?;
                audit = Some(match v {
                    "auditd" => AuditBackend::Auditd,
                    "syslog" => AuditBackend::Syslog,
                    "both" => AuditBackend::Both,
                    _ => return Err(malformed(line, key)),
                });
            }
            "debug" => {
                let v = single(&rest, line, key)?;
                set_once(&mut debug, line, key)?;
                debug = Some(parse_bool(v, line, key)?);
            }
            other => {
                return Err(ParseError::UnknownKey {
                    line,
                    key: other.to_owned(),
                });
            }
        }
    }

    if servers.is_empty() {
        return Err(ParseError::MissingRequired { key: "server" });
    }
    let protocol = protocol.ok_or(ParseError::MissingRequired { key: "protocol" })?;

    Ok(ParsedConfig {
        servers,
        protocol,
        timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        probe_timeout: probe_timeout.unwrap_or(DEFAULT_PROBE_TIMEOUT),
        retries: retries.unwrap_or(DEFAULT_RETRIES),
        nas_identifier,
        nas_ip,
        source_ip,
        // Strict by default (SECURITY_DESIGN.md §5).
        require_message_authenticator: require_ma.unwrap_or(true),
        // Emit to both backends unless narrowed (IMPLEMENTATION_SPEC.md §8:
        // native auditd is the default expectation, syslog always available).
        audit: audit.unwrap_or(AuditBackend::Both),
        debug: debug.unwrap_or(false),
    })
}

/// Require exactly one value token for a scalar key.
fn single<'a>(rest: &[&'a str], line: usize, key: &str) -> Result<&'a str, ParseError> {
    match rest {
        [only] => Ok(only),
        _ => Err(malformed(line, key)),
    }
}

/// Reject a second occurrence of a scalar key.
fn set_once<T>(slot: &mut Option<T>, line: usize, key: &str) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::DuplicateKey {
            line,
            key: key.to_owned(),
        });
    }
    Ok(())
}

fn parse_u32(v: &str, line: usize, key: &str) -> Result<u32, ParseError> {
    v.parse::<u32>().map_err(|_| malformed(line, key))
}

fn parse_bool(v: &str, line: usize, key: &str) -> Result<bool, ParseError> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(malformed(line, key)),
    }
}

fn malformed(line: usize, key: &str) -> ParseError {
    ParseError::MalformedValue {
        line,
        key: key.to_owned(),
    }
}
