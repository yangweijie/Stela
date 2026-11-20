//! The credential manager service `scrd`: ACM's context pool, with the
//! credentials and the policy check a password authorization uses.
//!
//! **Wire.** 26A434 kernel VM addresses. `AppleCredentialManager` finds the
//! `sep-endpoint,scrd` nub (`ACMKernelUtils::waitForSEPEndpoint`
//! 0xfffffe00092e3528, 5 s per client) and registers one 16 KiB buffer each
//! way (`getSEPEndpoint` 0xfffffe00092e1568). `handleSEPMessage`
//! 0xfffffe00092e092c asserts that a reply names `SCRD_ENDPOINT`, 10.
//! `sendSEPCommand` 0xfffffe00092deda8 sends the frame's tag as its request,
//! and the opcode and parameter as the little-endian input length. Request
//! [`PAYLOAD`] leads its input with an `SCRDRequestPayload_v1`: a version
//! byte, a u16 size and at +4 the u32 request ID. A reply echoes the request
//! in its tag, carries the output length in the same two bytes and its
//! status in the data word. Request [`PAYLOAD`]'s output must lead with an
//! `SCRDResponsePayloadHead`: a nonzero version, a u16 size and the request
//! ID, at least [`HEAD_BYTES`] in all, or the kernel logs an assertion.
//! The bytes after the head are the command's output
//! (`sendSEPCommand`+0x4e0..+0x5c0).
//!
//! **Status.** 26B123 VAs from here on. The kernel returns the reply's
//! status word as the command's ACM error (`sendSEPCommand`
//! 0xfffffe00092f0890, status at +0x158 of the manager, returned by
//! `_performCommand` 0xfffffe00092f007c), and its callers compare it with
//! ACM's own codes: `LibCall_ACMContextCreate` 0xfffffe00092fa928 falls back
//! from command 36 to 1 on kACMErrorBadParameter, -3. So a modeled ACM
//! failure is answered with its ACM code as the status.
//!
//! **Commands.** An ACM command follows the 28-byte request payload: u32
//! `SCRD`, the command byte, two bytes and the command version, then its
//! input (`LibCall_BuildCommand` 0xfffffe00092fa718). The reference for
//! every command is ACM's own executor, which the AppleCredentialManager
//! kext carries for its simulated mode (`_ProcessRawCommand`
//! 0xfffffe00092954b8, names in `__cmdTable` 0xfffffe000cb3cc78); [`acm`]
//! cites it per command. [`acm::Credentials`] serves context create and
//! delete, handle queries, externalization, PassphraseEntered credentials,
//! credential queries and removal, DeviceOwner policy verification
//! ([`policy`]), the logging level and Lockdown Mode's environment variable.
//! Every other command is refused with [`UNSUPPORTED`] and named once in the
//! diagnostics.
//!
//! **Passwords.** ACM never checks a passphrase: `addCredential`
//! 0xfffffe0009290c80 stores it, and `verifyPolicyDeviceOwnerAuthenticationImpl`
//! 0xfffffe000929eeb0 looks only for a PasscodeValidated credential. The
//! password is checked by the keystore's verify ([`super::keystore`]), which
//! reads the PassphraseEntered credential of the context its secret names
//! through [`Link`] and, when the passphrase opens the user's keybag, grants
//! PasscodeValidated to the request's context.
mod acm;
mod policy;
#[cfg(test)]
pub(crate) mod tests;

pub use acm::{Credentials, HANDLE_BYTES, Handle, Link, Unlinked};

use super::{
    Entropy,
    endpoint::Service,
    message::Frame,
    transaction::{Answer, Payload, Refusal},
};
use alloc::vec::Vec;
use stela_contracts::refuse;
use zeroize::Zeroizing;

/// `SCRD_ENDPOINT`.
pub const ID: u8 = 10;
/// `kIOReturnUnsupported`: the answer to a command this model refuses.
const UNSUPPORTED: u32 = 0xe000_02c7;
/// The request whose buffers carry SCRD payloads.
const PAYLOAD: u8 = 4;
/// `SCRDRequestPayload_v1`, whose request ID ends at byte 8.
const REQUEST_BYTES: usize = 28;
/// An ACM command's first word, `SCRD` in little-endian order.
const COMMAND_MAGIC: &[u8; 4] = b"DRCS";
/// An ACM command's bytes before its input.
const COMMAND_BYTES: usize = 8;
/// The request bytes observation may record: the payload and the command
/// head, never an input, which may hold a passphrase.
pub const OBSERVABLE_BYTES: usize = REQUEST_BYTES + COMMAND_BYTES;
/// The largest request: the one 16 KiB buffer the kernel registers.
const LARGEST_REQUEST: usize = 0x4000;
/// `sizeof(SCRDResponsePayloadHead)` as `sendSEPCommand` requires it.
const HEAD_BYTES: usize = 12;
/// The version of `SCRDResponsePayload_v2`.
const RESPONSE_VERSION: u8 = 2;

pub fn service() -> Service {
    Service {
        id: ID,
        name: u32::from_be_bytes(*b"scrd"),
        capacities: [1, 1, 1, 1],
    }
}

/// The reply to `frame`, with `length` output bytes.
fn reply(frame: Frame, length: u16, status: u32) -> Frame {
    let [opcode, parameter] = length.to_le_bytes();
    Frame {
        service: ID,
        tag: frame.tag,
        opcode,
        parameter,
        data: status,
    }
}

/// The answer to a request refused before its buffers were read.
pub fn failure(frame: Frame) -> Frame {
    reply(frame, 0, UNSUPPORTED)
}

/// Serve `frame` from `credentials`: write the response head and the
/// command's output and answer with its status, or refuse a command that is
/// not modeled with the head alone.
pub fn request(
    frame: Frame,
    payload: &mut dyn Payload,
    credentials: &mut Credentials,
    entropy: &mut dyn Entropy,
) -> Result<Frame, Refusal> {
    let length = usize::from(u16::from_le_bytes([frame.opcode, frame.parameter]));
    if frame.tag != PAYLOAD || !(OBSERVABLE_BYTES..=LARGEST_REQUEST).contains(&length) {
        return Err(Refusal::answered(
            refuse!(
                "SEP credential manager request is not an ACM command",
                tag = frame.tag,
                length
            ),
            Answer::frame(failure(frame)),
        ));
    }
    // The input may hold a passphrase: its bytes are zeroed when dropped.
    let mut bytes = Zeroizing::new(alloc::vec![0; length]);
    payload
        .input(&mut bytes)
        .map_err(|reason| Refusal::answered(reason, Answer::frame(failure(frame))))?;
    let mut output = head(&bytes);
    let command = &bytes[REQUEST_BYTES..];
    if &command[..COMMAND_MAGIC.len()] != COMMAND_MAGIC {
        return Err(Refusal::answered(
            refuse!("SEP credential manager request is not an ACM command"),
            Answer {
                frame: reply(frame, HEAD_BYTES as u16, UNSUPPORTED),
                output,
            },
        ));
    }
    let head = acm::Head {
        command: command[4],
        argument: command[5],
        version: command[7],
    };
    let status = match credentials.execute(head, &command[COMMAND_BYTES..], entropy) {
        Ok(served) => {
            output.extend_from_slice(&served);
            0
        }
        Err(acm::Failure::Acm(code)) => code as u32,
        Err(acm::Failure::Unmodeled(reason)) => {
            return Err(Refusal::answered(
                reason,
                Answer {
                    frame: reply(frame, HEAD_BYTES as u16, UNSUPPORTED),
                    output,
                },
            ));
        }
    };
    payload
        .output(&output)
        .map_err(|reason| Refusal::answered(reason, Answer::frame(failure(frame))))?;
    Ok(reply(frame, output.len() as u16, status))
}

fn head(request: &[u8]) -> Vec<u8> {
    let mut head = alloc::vec![0; HEAD_BYTES];
    head[0] = RESPONSE_VERSION;
    head[2..4].copy_from_slice(&(HEAD_BYTES as u16).to_le_bytes());
    head[4..8].copy_from_slice(&request[4..8]);
    head
}
