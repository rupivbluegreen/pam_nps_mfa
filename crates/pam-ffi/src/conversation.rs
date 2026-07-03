//! Safe conversation layer over the FFI shim.
//!
//! Defines the [`Conversation`] abstraction the flow is written against (so
//! tests drive the flow with a fake, no live PAM handle needed), the real
//! [`PamConversation`] backed by `ffi::converse`, and the A4-sanitizing
//! prompt helper for network-supplied challenge text.
//!
//! Secret handling: a prompt reply arrives as a [`secrets::SecretString`]
//! (already copied out of — and wiped from — the conversation's malloc'd
//! buffer by the FFI layer) and is zeroized on drop.

use secrets::SecretString;

use crate::ffi;

/// Text shown when prompting for a one-time code if the server supplied no
/// printable Reply-Message.
pub const DEFAULT_OTP_PROMPT: &str = "Verification code: ";

/// The conversation could not be run or produced no usable reply. Carries no
/// message bytes, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvError {
    /// No conversation available, the application refused, or no reply came
    /// back for a prompt.
    Failed,
}

/// What the flow needs from PAM's conversation: show text, and collect an
/// echo-off reply. Object safe so [`crate::flow`] takes `&mut dyn
/// Conversation` and tests substitute a fake.
pub trait Conversation {
    /// Show informational text (PAM_TEXT_INFO), e.g. the "approve the
    /// sign-in on your device" push notice. Implementations may drop it
    /// (PAM_SILENT), but a transport/protocol failure is an error.
    fn info(&mut self, text: &str) -> Result<(), ConvError>;

    /// Prompt with echo off (PAM_PROMPT_ECHO_OFF) and return the reply.
    fn prompt_echo_off(&mut self, prompt: &str) -> Result<SecretString, ConvError>;
}

/// Prompt for the second factor named by *network-supplied* challenge text
/// (an Access-Challenge Reply-Message). The text is sanitized first
/// (SPEC_AMENDMENTS.md A4 — strips control bytes so a peer cannot inject
/// terminal escapes into the login prompt); if nothing printable remains,
/// [`DEFAULT_OTP_PROMPT`] is used.
pub fn prompt_response(
    conv: &mut dyn Conversation,
    network_text: &str,
) -> Result<SecretString, ConvError> {
    let sanitized = pap::sanitize_reply_message(network_text.as_bytes());
    let prompt = if sanitized.is_empty() {
        DEFAULT_OTP_PROMPT
    } else {
        &sanitized
    };
    conv.prompt_echo_off(prompt)
}

/// The real conversation, backed by the application's `pam_conv` via the FFI
/// shim. Honors `PAM_SILENT` by dropping informational text (prompts are
/// never dropped — they collect credentials).
pub struct PamConversation {
    pam: ffi::Pam,
    silent: bool,
}

impl PamConversation {
    pub(crate) fn new(pam: ffi::Pam, silent: bool) -> Self {
        Self { pam, silent }
    }
}

impl Conversation for PamConversation {
    fn info(&mut self, text: &str) -> Result<(), ConvError> {
        if self.silent {
            return Ok(());
        }
        ffi::converse(self.pam, &[(ffi::style::PAM_TEXT_INFO, clamp(text))])
            .map(|_| ())
            .map_err(|_| ConvError::Failed)
    }

    fn prompt_echo_off(&mut self, prompt: &str) -> Result<SecretString, ConvError> {
        let mut replies = ffi::converse(self.pam, &[(ffi::style::PAM_PROMPT_ECHO_OFF, clamp(prompt))])
            .map_err(|_| ConvError::Failed)?;
        // Exactly one message was sent; a missing reply fails closed.
        replies.pop().flatten().ok_or(ConvError::Failed)
    }
}

/// Clamp text to fit a `pam_message` (PAM_MAX_MSG_SIZE including the NUL),
/// on a char boundary, so an over-long (already sanitized) Reply-Message
/// truncates instead of failing the conversation.
fn clamp(text: &str) -> &str {
    const MAX: usize = 511; // PAM_MAX_MSG_SIZE - 1 for the NUL terminator
    if text.len() <= MAX {
        return text;
    }
    let mut end = MAX;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedConv {
        infos: Vec<String>,
        reply: Option<&'static str>,
    }

    impl Conversation for ScriptedConv {
        fn info(&mut self, text: &str) -> Result<(), ConvError> {
            self.infos.push(text.to_owned());
            Ok(())
        }
        fn prompt_echo_off(&mut self, prompt: &str) -> Result<SecretString, ConvError> {
            self.infos.push(format!("prompt:{prompt}"));
            self.reply
                .map(SecretString::from_text)
                .ok_or(ConvError::Failed)
        }
    }

    #[test]
    fn prompt_response_sanitizes_network_text() {
        let mut conv = ScriptedConv {
            infos: Vec::new(),
            reply: Some("123456"),
        };
        // Terminal-escape injection attempt gets stripped (A4).
        let got = prompt_response(&mut conv, "Enter\x1b[2Jcode:").expect("reply");
        assert_eq!(got.expose_secret(), "123456");
        assert_eq!(conv.infos, vec!["prompt:Enter[2Jcode:"]);
    }

    #[test]
    fn prompt_response_falls_back_when_nothing_printable_remains() {
        let mut conv = ScriptedConv {
            infos: Vec::new(),
            reply: Some("x"),
        };
        prompt_response(&mut conv, "\x07\x1b\x00").expect("reply");
        assert_eq!(conv.infos, vec![format!("prompt:{DEFAULT_OTP_PROMPT}")]);
    }

    #[test]
    fn clamp_truncates_on_char_boundaries() {
        let long = "a".repeat(600);
        assert_eq!(clamp(&long).len(), 511);
        let multi = format!("{}é", "a".repeat(510)); // é straddles the limit
        let clamped = clamp(&multi);
        assert!(clamped.len() <= 511);
        assert!(clamped.is_char_boundary(clamped.len()));
        assert_eq!(clamp("short"), "short");
    }
}
