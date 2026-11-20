//! ACM's commands over its pool of credential sets (contexts), after the
//! reference executor `_ProcessRawCommand` (26B123 VA 0xfffffe00092954b8).
//!
//! **Contexts.** `CreateCredentialSet` 0xfffffe0009296b3c takes exactly a
//! u32, the session UID, and makes a set with a random 16-byte handle
//! (`Util_GenerateRandom`, never the null handle `__nullHandle`, never the
//! all-0xff global set's, never one in use; retried), the tracking number
//! `counter % 99901 + 100` from a counter that starts at 0
//! (`__credSetTrackingNumberCounter`, +0x198..+0x1c8) and the
//! non-auto-disposable flag for command 52. Its output is the handle, the
//! logging level byte and the u32 tracking number; command 1 stops after
//! the level. At most 0xc0 sets are non-auto-disposable (-31, +0x2ac); when
//! all 0x100 places are used, the least recently used auto-disposable set is
//! deleted for the new one (+0x354..+0x440).
//!
//! **Credentials.** `DeserializeAddCredential` 0xfffffe00092d9f5c reads the
//! handle, a credential and a u32 scope. A credential is 32 bytes of header
//! (u32 type at 0, domain at 4 below 4, a u32 at 8 at most 0x100, the data
//! length at 0x1c) and its data, whose length is fixed per type
//! (`DeserializeCredential` 0xfffffe00092d9094): PassphraseEntered (2) has
//! 0x88 bytes, a u32 purpose, the u32 passphrase length and 128 bytes
//! (`ACMCredentialSetProperty` in LocalAuthenticationCore 0x1b24fb0d4
//! stores at most 0x80 bytes at data+8 with the length at data+4);
//! PasscodeValidated (1) has 0x1c. Scope bit 0 is the context, bit 1 the
//! global set (`addCredential` 0xfffffe0009290c80, "scope ==
//! kACMScopeContext" with scope 1).
//!
//! **Environment.** GetEnvironmentVariable answers Lockdown Mode (41) as off
//! and the one-byte variables the engine's initialization sets as it sets
//! them; variables set later, by the AP or with data providers, are not
//! modeled.
//!
//! **Model.** Only PassphraseEntered is added from the AP: PasscodeValidated
//! comes from the keystore's verify ([`Link::passcode_validated`]), so no
//! client can claim a passcode it did not give. The global set, other
//! credential types, credential lifetimes beyond their context, usage
//! counts and ACL parameters are not modeled; each is named once when a
//! request needs it.
use super::super::Entropy;
use super::super::observe::Journal;
use super::policy;
use crate::Result;
use alloc::{format, string::String, vec, vec::Vec};
use stela_contracts::refuse;
use zeroize::Zeroizing;

pub const HANDLE_BYTES: usize = 16;
/// An ACM context's handle, which is also its external form.
pub type Handle = [u8; HANDLE_BYTES];
const NULL_HANDLE: Handle = [0; HANDLE_BYTES];
const GLOBAL_HANDLE: Handle = [0xff; HANDLE_BYTES];

/// `handleExists` 0xfffffe0009293480 on a context never externalized.
const NOT_EXTERNALIZED: i32 = -1;
/// `findCredentialSet` 0xfffffe000928b188 for a handle in no set.
const NO_CONTEXT: i32 = -2;
/// kACMErrorBadParameter.
pub(super) const BAD_PARAMETER: i32 = -3;
/// The non-auto-disposable sets are all used.
const POOL_FULL: i32 = -31;

const CONTEXT_CREATE: u8 = 1;
const CONTEXT_DELETE: u8 = 2;
const VERIFY_POLICY: u8 = 3;
const CONTAINS_CREDENTIAL_TYPE: u8 = 4;
const ADD_CREDENTIAL: u8 = 5;
const REMOVE_CREDENTIAL_BY_TYPE: u8 = 9;
/// Also what `performSCRDInitialization` sends with no input: the level is
/// the command head's byte 5 (`_ProcessRawCommand`+0x678).
const SET_LOGGING_LEVEL: u8 = 10;
const HANDLE_EXISTS: u8 = 18;
const EXTERNALIZE_CONTEXT: u8 = 19;
const GET_SUPPORTED_VERSION: u8 = 22;
const GET_ENVIRONMENT_VARIABLE: u8 = 25;
const CONTEXT_CREATE_WITH_TRACKING: u8 = 36;
const HANDLE_EXISTS_WITH_TRACKING: u8 = 37;
const CONTEXT_CREATE_NON_AUTO_DISPOSABLE_WITH_TRACKING: u8 = 52;

/// `_getVersion` 0xfffffe0009299478's answer.
const SUPPORTED_VERSION: u8 = 2;
/// `gACMLoggingLevel`'s initial value in the kext (0xfffffe000cb40988),
/// taken as sepOS's until the kernel sets one.
const INITIAL_LOGGING_LEVEL: u8 = 0x28;
/// The environment variable `LDMCheckParity` compares with NVRAM.
const LOCKDOWN_MODE: u32 = 41;
const LOCKDOWN_OFF: u8 = 0;
/// The one-byte environment variables `InitCredentialEngine`
/// 0xfffffe0009294a40 sets, whose slots (`__envTable` 0xfffffe000cb3d520,
/// 0x98 bytes each) any caller may read and nothing else in the executor
/// sets: 5 (+0x150), 6, the biometry type `biometryTypePresent` reads
/// (+0x98, 0: none), 7 (+0x2ac), 26 (+0x2c8), 33 (+0x2e4, 1) and 34
/// (+0x300). Variable 23 (from the engine's boot parameters), 24 (the
/// engine's build date) and those with data providers are not among them.
const INITIAL_VARIABLES: [(u32, u8); 6] = [(5, 0), (6, 0), (7, 0), (26, 0), (33, 1), (34, 0)];
/// The executor's answer to a command shorter than its input
/// (`Exec_ACMGetEnvironmentVariable`+0x194).
const SHORT_COMMAND: i32 = -5;

const SETS: usize = 0x100;
const NON_AUTO_DISPOSABLE_SETS: usize = 0xc0;
const TRACKING_MODULUS: u32 = 99_901;
const TRACKING_BASE: u32 = 100;
/// Tries for a fresh random handle; a bound of the model, not of ACM.
const HANDLE_TRIES: usize = 8;
/// Credentials one context holds; a bound of the model, not of ACM.
const CREDENTIALS_PER_SET: usize = 16;

pub(super) const PASSCODE_VALIDATED: u32 = 1;
const PASSPHRASE_ENTERED: u32 = 2;
const CREDENTIAL_HEADER: usize = 0x20;
const PASSPHRASE_DATA: usize = 0x88;
const PASSPHRASE_MAX: usize = 0x80;
const PASSCODE_VALIDATED_DATA: usize = 0x1c;
const SCOPE_CONTEXT: u32 = 1;
const ADD_INPUT_MIN: usize = 0x34;
const TYPE_AND_SCOPE_INPUT: usize = HANDLE_BYTES + 8;

/// A command's head after the magic.
#[derive(Clone, Copy)]
pub(super) struct Head {
    pub command: u8,
    /// Byte 5: the level of [`SET_LOGGING_LEVEL`].
    pub argument: u8,
    /// Byte 7: the version the requirement serializer follows.
    pub version: u8,
}

/// Why a command produced no output.
pub(super) enum Failure {
    /// The executor's own answer: its ACM error code.
    Acm(i32),
    /// Outside the model: refused and reported.
    Unmodeled(stela_contracts::Refusal),
}

impl From<i32> for Failure {
    fn from(code: i32) -> Self {
        Self::Acm(code)
    }
}

/// What the keystore asks of the credential manager inside the SEP.
pub trait Link {
    /// The passphrase of the newest PassphraseEntered credential in
    /// `context`.
    fn passphrase(&self, context: &Handle) -> Result<Zeroizing<Vec<u8>>>;
    fn exists(&self, context: &Handle) -> bool;
    /// Give `context` a PasscodeValidated credential.
    fn passcode_validated(&mut self, context: &Handle) -> Result<()>;
}

/// No credential manager: every ACM reference is refused.
pub struct Unlinked;

impl Link for Unlinked {
    fn passphrase(&self, _: &Handle) -> Result<Zeroizing<Vec<u8>>> {
        Err(refuse!(
            "SEP keybag verify names an ACM context, and no credential manager runs"
        ))
    }
    fn exists(&self, _: &Handle) -> bool {
        false
    }
    fn passcode_validated(&mut self, _: &Handle) -> Result<()> {
        Err(refuse!(
            "SEP keybag verify names an ACM context, and no credential manager runs"
        ))
    }
}

struct Credential {
    kind: u32,
    data: Zeroizing<Vec<u8>>,
}

struct Set {
    handle: Handle,
    tracking: u32,
    non_auto_disposable: bool,
    externalized: bool,
    /// Its place in the use order: larger is more recent.
    used: u64,
    credentials: Vec<Credential>,
}

/// ACM's credential sets, as the SEP keeps them for this boot.
pub struct Credentials {
    sets: Vec<Set>,
    tracking: u32,
    uses: u64,
    logging: u8,
    diagnostics: Journal,
    reported: Vec<String>,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            sets: Vec::new(),
            tracking: 0,
            uses: 0,
            logging: INITIAL_LOGGING_LEVEL,
            diagnostics: Journal::default(),
            reported: Vec::new(),
        }
    }
}

impl Credentials {
    /// Name what is not modeled, once per boot each; never a secret.
    fn report(&mut self, line: String) {
        if !self.reported.contains(&line) {
            self.diagnostics
                .record(format!("SEP credential manager: {line}"));
            self.reported.push(line);
        }
    }

    fn unmodeled(&mut self, line: String, reason: stela_contracts::Refusal) -> Failure {
        self.report(line);
        Failure::Unmodeled(reason)
    }

    /// The diagnostics lines waiting for the boot log.
    pub(in super::super) fn diagnostics(&mut self) -> impl Iterator<Item = String> + '_ {
        self.diagnostics.drain()
    }

    /// The contexts in the pool.
    #[cfg(test)]
    pub fn contexts(&self) -> usize {
        self.sets.len()
    }

    /// Run one command on `input`, the bytes after its head.
    pub(super) fn execute(
        &mut self,
        head: Head,
        input: &[u8],
        entropy: &mut dyn Entropy,
    ) -> core::result::Result<Vec<u8>, Failure> {
        match head.command {
            GET_SUPPORTED_VERSION => {
                if input.len() != 1 {
                    return Err(BAD_PARAMETER.into());
                }
                Ok(vec![SUPPORTED_VERSION])
            }
            SET_LOGGING_LEVEL => {
                self.logging = head.argument;
                Ok(Vec::new())
            }
            CONTEXT_CREATE
            | CONTEXT_CREATE_WITH_TRACKING
            | CONTEXT_CREATE_NON_AUTO_DISPOSABLE_WITH_TRACKING => self.create(
                input,
                head.command == CONTEXT_CREATE_NON_AUTO_DISPOSABLE_WITH_TRACKING,
                head.command != CONTEXT_CREATE,
                entropy,
            ),
            CONTEXT_DELETE => {
                let handle = handle_input(input)?;
                usable(&handle)?;
                let at = self.position(&handle)?;
                self.sets.remove(at);
                Ok(Vec::new())
            }
            HANDLE_EXISTS | HANDLE_EXISTS_WITH_TRACKING => {
                let handle = handle_input(input)?;
                if handle == GLOBAL_HANDLE {
                    return Err(self.global("handle query"));
                }
                let set = self.find(&handle)?;
                if !set.externalized {
                    return Err(NOT_EXTERNALIZED.into());
                }
                let tracking = set.tracking;
                // handleExistsSerialized 0xfffffe0009298678: u32 1, then for
                // 37 the tracking number at byte 5. Byte 4 is not written
                // there; this model sends 0.
                let mut output = vec![0; 5];
                output[0] = 1;
                if head.command == HANDLE_EXISTS_WITH_TRACKING {
                    output.extend_from_slice(&tracking.to_le_bytes());
                }
                Ok(output)
            }
            EXTERNALIZE_CONTEXT => {
                let handle = handle_input(input)?;
                usable(&handle)?;
                self.find(&handle)?.externalized = true;
                Ok(Vec::new())
            }
            ADD_CREDENTIAL => self.add(input),
            CONTAINS_CREDENTIAL_TYPE | REMOVE_CREDENTIAL_BY_TYPE => {
                let (handle, kind, scope) = type_and_scope(input)?;
                if handle == NULL_HANDLE {
                    return Err(BAD_PARAMETER.into());
                }
                if scope != SCOPE_CONTEXT || handle == GLOBAL_HANDLE {
                    return Err(self.global("credential scope other than the context"));
                }
                let set = self.find(&handle)?;
                if head.command == REMOVE_CREDENTIAL_BY_TYPE {
                    set.credentials.retain(|credential| credential.kind != kind);
                    return Ok(Vec::new());
                }
                // containsCredentialType 0xfffffe0009292c08 fails a type
                // the set lacks with kACMErrorNotFound, -7, which
                // containsCredentialTypeSerialized 0xfffffe000929823c
                // answers as a u32 0.
                let found = set.credentials.iter().any(|c| c.kind == kind);
                Ok(u32::from(found).to_le_bytes().to_vec())
            }
            VERIFY_POLICY => self.verify_policy(head.version, input),
            GET_ENVIRONMENT_VARIABLE => self.environment_variable(input),
            command => {
                let leading = input.get(..4).map_or(0, |word| {
                    u32::from_le_bytes(word.try_into().expect("4 bytes"))
                });
                Err(self.unmodeled(
                    format!("command {command} is not implemented"),
                    refuse!(
                        "SEP credential manager command is not implemented",
                        command,
                        input = input.len(),
                        leading = %format_args!("{leading:#x}")
                    ),
                ))
            }
        }
    }

    /// GetEnvironmentVariable (`Exec_ACMGetEnvironmentVariable`
    /// 0xfffffe000928948c): no input is -3, less than the u32 variable is
    /// -5, and bytes after it are not read. The variables
    /// `InitCredentialEngine` sets ([`INITIAL_VARIABLES`]) answer their byte,
    /// as `Env_GetVariable` 0xfffffe00092c0aa8 copies a stored value; every
    /// other variable is outside the model.
    fn environment_variable(&mut self, input: &[u8]) -> core::result::Result<Vec<u8>, Failure> {
        if input.is_empty() {
            return Err(BAD_PARAMETER.into());
        }
        let Some(word) = input.get(..4) else {
            return Err(SHORT_COMMAND.into());
        };
        let variable = u32::from_le_bytes(word.try_into().expect("4 bytes"));
        if variable == LOCKDOWN_MODE {
            // LDMCheckParity reads one byte: Lockdown Mode is off, so
            // enabling it does not survive a reboot.
            return Ok(vec![LOCKDOWN_OFF]);
        }
        if let Some((_, value)) = INITIAL_VARIABLES.iter().find(|(id, _)| *id == variable) {
            return Ok(vec![*value]);
        }
        Err(self.unmodeled(
            format!("environment variable {variable} is not modeled"),
            refuse!(
                "SEP credential manager does not model this environment variable",
                variable
            ),
        ))
    }

    fn global(&mut self, what: &'static str) -> Failure {
        self.unmodeled(
            format!("the global credential set ({what}) is not modeled"),
            refuse!(
                "SEP credential manager does not model the global credential set",
                what
            ),
        )
    }

    fn create(
        &mut self,
        input: &[u8],
        non_auto_disposable: bool,
        tracked: bool,
        entropy: &mut dyn Entropy,
    ) -> core::result::Result<Vec<u8>, Failure> {
        // The session UID: CreateCredentialSet logs it and keeps it in the
        // set; nothing this model serves reads it.
        if input.len() != 4 {
            return Err(BAD_PARAMETER.into());
        }
        let pinned = self
            .sets
            .iter()
            .filter(|set| set.non_auto_disposable)
            .count();
        if non_auto_disposable && pinned >= NON_AUTO_DISPOSABLE_SETS {
            return Err(POOL_FULL.into());
        }
        let mut handle = NULL_HANDLE;
        let mut fresh = false;
        for _ in 0..HANDLE_TRIES {
            entropy.fill(&mut handle).map_err(Failure::Unmodeled)?;
            if handle != NULL_HANDLE
                && handle != GLOBAL_HANDLE
                && self.sets.iter().all(|set| set.handle != handle)
            {
                fresh = true;
                break;
            }
        }
        if !fresh {
            return Err(Failure::Unmodeled(refuse!(
                "SEP credential manager drew no fresh context handle"
            )));
        }
        if self.sets.len() >= SETS {
            // The least recently used auto-disposable set gives way. With
            // none, the reference deletes nothing and fails (inferred:
            // deleteCredentialSetEntry of no entry).
            let oldest = self
                .sets
                .iter()
                .enumerate()
                .filter(|(_, set)| !set.non_auto_disposable)
                .min_by_key(|(_, set)| set.used)
                .map(|(at, _)| at)
                .ok_or(BAD_PARAMETER)?;
            self.sets.remove(oldest);
        }
        let tracking = self.tracking % TRACKING_MODULUS + TRACKING_BASE;
        self.tracking = self.tracking.wrapping_add(1);
        self.uses += 1;
        self.sets.push(Set {
            handle,
            tracking,
            non_auto_disposable,
            externalized: false,
            used: self.uses,
            credentials: Vec::new(),
        });
        let mut output = handle.to_vec();
        output.push(self.logging);
        if tracked {
            output.extend_from_slice(&tracking.to_le_bytes());
        }
        Ok(output)
    }

    fn position(&self, handle: &Handle) -> core::result::Result<usize, Failure> {
        self.sets
            .iter()
            .position(|set| set.handle == *handle)
            .ok_or(Failure::Acm(NO_CONTEXT))
    }

    /// The set of `handle`, now its most recent use.
    fn find(&mut self, handle: &Handle) -> core::result::Result<&mut Set, Failure> {
        if *handle == NULL_HANDLE {
            return Err(BAD_PARAMETER.into());
        }
        let at = self.position(handle)?;
        self.uses += 1;
        let set = &mut self.sets[at];
        set.used = self.uses;
        Ok(set)
    }

    fn add(&mut self, input: &[u8]) -> core::result::Result<Vec<u8>, Failure> {
        if input.len() < ADD_INPUT_MIN {
            return Err(BAD_PARAMETER.into());
        }
        let handle: Handle = input[..HANDLE_BYTES].try_into().expect("16 bytes");
        let header = &input[HANDLE_BYTES..HANDLE_BYTES + CREDENTIAL_HEADER];
        let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
        let (kind, domain, count, length) = (word(0), word(4), word(8), word(0x1c) as usize);
        if !(1..=0x17).contains(&kind) || domain >= 4 || count > 0x100 {
            return Err(BAD_PARAMETER.into());
        }
        if kind != PASSPHRASE_ENTERED {
            return Err(self.unmodeled(
                format!("adding credential type {kind} is not modeled"),
                refuse!(
                    "SEP credential manager does not add this credential type",
                    kind
                ),
            ));
        }
        let data_at = HANDLE_BYTES + CREDENTIAL_HEADER;
        if length != PASSPHRASE_DATA || input.len() < data_at + length + 4 {
            return Err(BAD_PARAMETER.into());
        }
        let data = &input[data_at..data_at + length];
        let passphrase = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) as usize;
        if passphrase > PASSPHRASE_MAX {
            return Err(BAD_PARAMETER.into());
        }
        let scope = u32::from_le_bytes(
            input[data_at + length..data_at + length + 4]
                .try_into()
                .expect("4 bytes"),
        );
        if handle == NULL_HANDLE {
            return Err(BAD_PARAMETER.into());
        }
        if scope != SCOPE_CONTEXT || handle == GLOBAL_HANDLE {
            return Err(self.global("credential scope other than the context"));
        }
        let set = self.find(&handle)?;
        if set.credentials.len() >= CREDENTIALS_PER_SET {
            set.credentials.remove(0);
        }
        set.credentials.push(Credential {
            kind,
            data: Zeroizing::new(data.to_vec()),
        });
        Ok(Vec::new())
    }

    fn verify_policy(
        &mut self,
        version: u8,
        input: &[u8],
    ) -> core::result::Result<Vec<u8>, Failure> {
        let request = policy::Request::parse(input).map_err(Failure::Acm)?;
        let Some(policy) = policy::Policy::named(request.policy) else {
            let name = String::from_utf8_lossy(request.policy).into_owned();
            return Err(self.unmodeled(
                format!("policy {name} is not modeled"),
                refuse!("SEP credential manager does not model this policy", name),
            ));
        };
        if request.handle == GLOBAL_HANDLE {
            return Err(BAD_PARAMETER.into());
        }
        if request.parameters != 0 {
            self.report(String::from(
                "ACL parameters, such as credential age limits, are not evaluated",
            ));
        }
        let set = self.find(&request.handle)?;
        let passcode = set
            .credentials
            .iter()
            .any(|credential| credential.kind == PASSCODE_VALIDATED);
        let (satisfied, requirement) = match policy {
            policy::Policy::Biometrics => policy::biometrics(version),
            _ => policy::device_owner(policy, version, passcode),
        };
        if satisfied && !request.preflight {
            self.report(String::from(
                "credential usage counts are not kept: a PasscodeValidated credential lasts as long as its context",
            ));
        }
        let mut output = u32::from(satisfied).to_le_bytes().to_vec();
        output.extend_from_slice(&requirement);
        Ok(output)
    }
}

impl Link for Credentials {
    fn passphrase(&self, context: &Handle) -> Result<Zeroizing<Vec<u8>>> {
        let set = self
            .sets
            .iter()
            .find(|set| set.handle == *context)
            .ok_or(refuse!("SEP keybag verify's ACM secret names no context"))?;
        let credential = set
            .credentials
            .iter()
            .rev()
            .find(|credential| credential.kind == PASSPHRASE_ENTERED)
            .ok_or(refuse!(
                "SEP keybag verify's ACM context holds no entered passphrase"
            ))?;
        let length = u32::from_le_bytes(credential.data[4..8].try_into().expect("4 bytes"));
        Ok(Zeroizing::new(
            credential.data[8..8 + length as usize].to_vec(),
        ))
    }

    fn exists(&self, context: &Handle) -> bool {
        *context != NULL_HANDLE && self.sets.iter().any(|set| set.handle == *context)
    }

    fn passcode_validated(&mut self, context: &Handle) -> Result<()> {
        let set = self
            .sets
            .iter_mut()
            .find(|set| set.handle == *context)
            .ok_or(refuse!(
                "SEP keybag verify's ACM context was deleted before the verify ended"
            ))?;
        set.credentials
            .retain(|credential| credential.kind != PASSCODE_VALIDATED);
        if set.credentials.len() >= CREDENTIALS_PER_SET {
            set.credentials.remove(0);
        }
        set.credentials.push(Credential {
            kind: PASSCODE_VALIDATED,
            data: Zeroizing::new(vec![0; PASSCODE_VALIDATED_DATA]),
        });
        Ok(())
    }
}

fn handle_input(input: &[u8]) -> core::result::Result<Handle, Failure> {
    input.try_into().map_err(|_| Failure::Acm(BAD_PARAMETER))
}

/// Delete and externalize refuse the null and the global handle.
fn usable(handle: &Handle) -> core::result::Result<(), Failure> {
    if *handle == NULL_HANDLE || *handle == GLOBAL_HANDLE {
        return Err(BAD_PARAMETER.into());
    }
    Ok(())
}

/// Commands 4 and 9: the handle, a u32 credential type and a u32 scope.
fn type_and_scope(input: &[u8]) -> core::result::Result<(Handle, u32, u32), Failure> {
    if input.len() != TYPE_AND_SCOPE_INPUT {
        return Err(BAD_PARAMETER.into());
    }
    let word = |at: usize| u32::from_le_bytes(input[at..at + 4].try_into().expect("4 bytes"));
    Ok((
        input[..HANDLE_BYTES].try_into().expect("16 bytes"),
        word(16),
        word(20),
    ))
}
