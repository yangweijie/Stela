//! VerifyPolicy (command 3) for the DeviceOwner policies, after
//! `verifyPolicySerialized` 0xfffffe000929796c (26B123 VAs).
//!
//! **Request** (`DeserializeVerifyPolicy` 0xfffffe00092d63b8): the context
//! handle, the policy name with its NUL (at most 0x80 bytes before it), a
//! preflight byte, a u32 maximum global credential age, then parameters
//! (`deserializeParameters` 0xfffffe00092d6824): nothing, or a u32 count
//! below 11 and per parameter a u32 type, a u32 length and its bytes.
//!
//! **Policy** (`_verifyPolicy` 0xfffffe000928c3dc): DeviceOwner,
//! DeviceOwnerAuthentication, DeviceOwnerAuthenticated, UserPresence and,
//! with its admin flag, DeviceAdminAuthentication all call
//! `verifyPolicyDeviceOwnerAuthenticationImpl` 0xfffffe000929eeb0. It builds
//! a one-of-three requirement (type 7, threshold 1) over passcode (type 1,
//! its data flags given 0x20), biometry (3) and type 15, each child state 2
//! when a valid credential is found (PasscodeValidated, BiometryMatched,
//! type 9) and 1 otherwise; biometry is looked at only when a biometry type
//! is present, and the admin flag also accepts PasscodeValidated2 (10).
//! `ReqAlgo_EvaluateSubrequirements` 0xfffffe00092ac83c makes the root 2
//! when at least threshold children are 2. New requirements start in state 1
//! with the u32 at +8 set to 1 (`Util_AllocRequirement` 0xfffffe00092ae69c).
//!
//! **Reply**: a u32, 1 when the root is satisfied, then the requirement
//! (`SerializeRequirement` 0xfffffe00092d8524): per node a u32 type, u32
//! state, the u32 at +8 and the u32 data size, then a leaf's data, or for
//! type 7 the u32 threshold, the u32 child count and the children. The data
//! size is the allocation's from version 2 (+0xc) and the table at
//! 0xfffffe000744e228 below it, which differ only for biometry.
//!
//! HumanPresence, UserIdentificationWithBiometrics and
//! DeviceOwnerAuthenticationWithBiometrics call `verifyPolicyBiometrics`
//! 0xfffffe000929aec4: a lone biometry requirement (type 3,
//! `Util_CreateRequirement`), which stays as allocated, state 1, when
//! `biometryTypePresent` 0xfffffe000929ee34 reads environment variable 6 as
//! 0, and the call succeeds; `_verifyPolicy` answers satisfied only for state
//! 2 (+0x5ac).
//!
//! **Model.** No biometry and no watch credential exist on this machine
//! (environment variable 6 is 0, as `InitCredentialEngine` sets it), so
//! those children stay 1 and only PasscodeValidated satisfies the root. The
//! biometry child's 0xdd data bytes stay zero, as nothing is matched.
use super::acm::{BAD_PARAMETER, HANDLE_BYTES, Handle};
use alloc::vec::Vec;

const MAX_POLICY: usize = 0x80;
const MAX_PARAMETERS: u32 = 10;

const K_OF_N: u32 = 7;
const PASSCODE: u32 = 1;
const BIOMETRY: u32 = 3;
const WATCH: u32 = 15;
const REQUIRED: u32 = 1;
const SATISFIED: u32 = 2;
/// The u32 at +8 of every new requirement.
const DEFAULT_PLUS_EIGHT: u32 = 1;
/// The data of a one-of-n node: threshold, count, ten child pointers.
const K_OF_N_DATA: u32 = 0x58;
const PASSCODE_FLAGS: u32 = 0x20;
const PASSCODE_DATA: u32 = 4;
const BIOMETRY_DATA_V2: u32 = 0xdd;
const BIOMETRY_DATA_V1: u32 = 0x9c;

pub(super) struct Request<'a> {
    pub handle: Handle,
    pub policy: &'a [u8],
    pub preflight: bool,
    pub parameters: u32,
}

impl<'a> Request<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, i32> {
        if input.len() < HANDLE_BYTES {
            return Err(BAD_PARAMETER);
        }
        let handle: Handle = input[..HANDLE_BYTES].try_into().expect("16 bytes");
        let rest = &input[HANDLE_BYTES..];
        let length = rest
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(rest.len());
        if length > MAX_POLICY || rest.len() <= length {
            return Err(BAD_PARAMETER);
        }
        let policy = &rest[..length];
        // The NUL, the preflight byte and the u32 maximum age.
        let fixed = length + 1 + 1 + 4;
        if rest.len() < fixed {
            return Err(BAD_PARAMETER);
        }
        let preflight = rest[length + 1] != 0;
        let mut parameters = &rest[fixed..];
        let mut count = 0;
        if !parameters.is_empty() {
            let word = |bytes: &[u8]| -> Result<u32, i32> {
                Ok(u32::from_le_bytes(
                    bytes
                        .get(..4)
                        .ok_or(BAD_PARAMETER)?
                        .try_into()
                        .expect("4 bytes"),
                ))
            };
            count = word(parameters)?;
            if count > MAX_PARAMETERS {
                return Err(BAD_PARAMETER);
            }
            parameters = &parameters[4..];
            for _ in 0..count {
                if parameters.len() < 8 {
                    return Err(BAD_PARAMETER);
                }
                let length = word(&parameters[4..])? as usize;
                parameters = parameters.get(8 + length..).ok_or(BAD_PARAMETER)?;
            }
        }
        Ok(Self {
            handle,
            policy,
            preflight,
            parameters: count,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy {
    DeviceOwner,
    DeviceAdmin,
    /// `verifyPolicyBiometrics`'s policies.
    Biometrics,
}

impl Policy {
    pub fn named(name: &[u8]) -> Option<Self> {
        match name {
            b"DeviceOwner"
            | b"DeviceOwnerAuthentication"
            | b"DeviceOwnerAuthenticated"
            | b"UserPresence" => Some(Self::DeviceOwner),
            b"DeviceAdminAuthentication" => Some(Self::DeviceAdmin),
            b"HumanPresence"
            | b"UserIdentificationWithBiometrics"
            | b"DeviceOwnerAuthenticationWithBiometrics" => Some(Self::Biometrics),
            _ => None,
        }
    }
}

/// The biometry data size the requirement serializer gives for `version`.
fn biometry_data(version: u8) -> u32 {
    if version >= 2 {
        BIOMETRY_DATA_V2
    } else {
        BIOMETRY_DATA_V1
    }
}

/// A biometric policy on a machine with no biometry: never satisfied, and
/// its requirement is the biometry leaf as allocated, serialized for
/// `version`.
pub(super) fn biometrics(version: u8) -> (bool, Vec<u8>) {
    let data = biometry_data(version);
    let mut bytes = Vec::new();
    node(&mut bytes, BIOMETRY, REQUIRED, data);
    bytes.resize(bytes.len() + data as usize, 0);
    (false, bytes)
}

/// Whether `policy` is satisfied with or without a PasscodeValidated
/// credential (`passcode`), and its requirement serialized for `version`.
/// The admin flag would also accept PasscodeValidated2, which nothing here
/// creates, so both policies answer alike.
pub(super) fn device_owner(_policy: Policy, version: u8, passcode: bool) -> (bool, Vec<u8>) {
    let passcode_state = if passcode { SATISFIED } else { REQUIRED };
    let root_state = if passcode_state == SATISFIED {
        SATISFIED
    } else {
        REQUIRED
    };
    let biometry_data = biometry_data(version);
    let mut bytes = Vec::new();
    node(&mut bytes, K_OF_N, root_state, K_OF_N_DATA);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    node(&mut bytes, PASSCODE, passcode_state, PASSCODE_DATA);
    bytes.extend_from_slice(&PASSCODE_FLAGS.to_le_bytes());
    node(&mut bytes, BIOMETRY, REQUIRED, biometry_data);
    bytes.resize(bytes.len() + biometry_data as usize, 0);
    node(&mut bytes, WATCH, REQUIRED, 0);
    (root_state == SATISFIED, bytes)
}

fn node(bytes: &mut Vec<u8>, kind: u32, state: u32, data: u32) {
    for word in [kind, state, DEFAULT_PLUS_EIGHT, data] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
}
