//! Request and reply fixtures built from the recovered layouts (no captured
//! bytes): the 28-byte request payload, the command head, then the input.
use super::*;
use crate::Result;

pub(crate) struct Buffers {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

impl Payload for Buffers {
    fn input(&mut self, bytes: &mut [u8]) -> Result<()> {
        bytes.copy_from_slice(&self.input[..bytes.len()]);
        Ok(())
    }
    fn output(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.extend_from_slice(bytes);
        Ok(())
    }
}

/// Request 0x12345678's payload, then the head of `command` with
/// `argument` in byte 5 and `version` in byte 7, then `input`.
pub(crate) fn command_bytes(command: u8, argument: u8, version: u8, input: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(&[1, 0, 28, 0, 0x78, 0x56, 0x34, 0x12]);
    bytes.extend_from_slice(b"DRCS");
    bytes.extend_from_slice(&[command, argument, 0, version]);
    bytes.extend_from_slice(input);
    bytes
}

fn frame(tag: u8, length: usize) -> Frame {
    let [opcode, parameter] = (length as u16).to_le_bytes();
    Frame {
        service: ID,
        tag,
        opcode,
        parameter,
        data: 0,
    }
}

const HEAD: [u8; 12] = [2, 0, 12, 0, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0];

/// Deterministic entropy: 1, 2, 3, ...
pub(crate) fn counter() -> impl FnMut(&mut [u8]) -> Result<()> {
    let mut next = 0u8;
    move |bytes: &mut [u8]| {
        for byte in bytes {
            next = next.wrapping_add(1);
            *byte = next;
        }
        Ok(())
    }
}

/// Send `command` (version 2) and return the status and the output after
/// the response head, checking the frame and head.
pub(crate) fn ask(
    credentials: &mut Credentials,
    entropy: &mut dyn Entropy,
    command: u8,
    input: &[u8],
) -> (u32, Vec<u8>) {
    ask_version(credentials, entropy, command, 2, input)
}

fn ask_version(
    credentials: &mut Credentials,
    entropy: &mut dyn Entropy,
    command: u8,
    version: u8,
    input: &[u8],
) -> (u32, Vec<u8>) {
    let bytes = command_bytes(command, 0, version, input);
    let sent = frame(PAYLOAD, bytes.len());
    let mut buffers = Buffers {
        input: bytes,
        output: Vec::new(),
    };
    let answer = request(sent, &mut buffers, credentials, entropy).unwrap();
    assert_eq!(answer.tag, PAYLOAD);
    assert_eq!(
        usize::from(u16::from_le_bytes([answer.opcode, answer.parameter])),
        buffers.output.len()
    );
    assert_eq!(buffers.output[..12], HEAD);
    (answer.data, buffers.output[12..].to_vec())
}

/// The refusal of a command outside the model, with its answer checked.
fn refused(credentials: &mut Credentials, command: u8, input: &[u8]) -> Refusal {
    let bytes = command_bytes(command, 0, 2, input);
    let mut buffers = Buffers {
        input: bytes.clone(),
        output: Vec::new(),
    };
    let refusal = request(
        frame(PAYLOAD, bytes.len()),
        &mut buffers,
        credentials,
        &mut counter(),
    )
    .unwrap_err();
    let answer = refusal.answer.clone().unwrap();
    assert_eq!(answer.frame, reply(frame(PAYLOAD, 0), 12, UNSUPPORTED));
    assert_eq!(answer.output, HEAD);
    assert!(buffers.output.is_empty());
    refusal
}

const BAD_PARAMETER: u32 = -3i32 as u32;
const NO_CONTEXT: u32 = -2i32 as u32;
const NOT_EXTERNALIZED: u32 = -1i32 as u32;
const POOL_FULL: u32 = -31i32 as u32;

/// Create a context for UID 501 with command 36: (handle, tracking).
pub(crate) fn create(credentials: &mut Credentials, entropy: &mut dyn Entropy) -> (Handle, u32) {
    let (status, output) = ask(credentials, entropy, 36, &501u32.to_le_bytes());
    assert_eq!(status, 0);
    assert_eq!(output.len(), 21);
    (
        output[..16].try_into().unwrap(),
        u32::from_le_bytes(output[17..].try_into().unwrap()),
    )
}

/// AddCredential (5) of a PassphraseEntered credential: the handle, the
/// 32-byte header (type 2, data length 0x88 at 0x1c), the data (purpose,
/// passphrase length, 128 bytes) and scope 1.
pub(crate) fn add_passphrase(handle: &Handle, passphrase: &[u8], scope: u32) -> Vec<u8> {
    let mut input = handle.to_vec();
    let mut header = [0u8; 32];
    header[..4].copy_from_slice(&2u32.to_le_bytes());
    header[0x1c..].copy_from_slice(&0x88u32.to_le_bytes());
    input.extend_from_slice(&header);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&(passphrase.len() as u32).to_le_bytes());
    let mut bytes = [0u8; 128];
    bytes[..passphrase.len()].copy_from_slice(passphrase);
    input.extend_from_slice(&bytes);
    input.extend_from_slice(&scope.to_le_bytes());
    input
}

fn type_and_scope(handle: &Handle, kind: u32, scope: u32) -> Vec<u8> {
    let mut input = handle.to_vec();
    input.extend_from_slice(&kind.to_le_bytes());
    input.extend_from_slice(&scope.to_le_bytes());
    input
}

/// VerifyPolicy (3): the handle, the policy with its NUL, preflight, the
/// maximum global age and no parameters.
pub(crate) fn verify_policy(handle: &Handle, policy: &[u8], preflight: bool) -> Vec<u8> {
    let mut input = handle.to_vec();
    input.extend_from_slice(policy);
    input.push(0);
    input.push(preflight.into());
    input.extend_from_slice(&0u32.to_le_bytes());
    input
}

/// The DeviceOwner requirement: one of passcode (flags 0x20), biometry and
/// type 15, with the passcode child's state and the biometry data size.
fn device_owner_reply(passcode: u32, biometry: u32) -> Vec<u8> {
    let words = |bytes: &mut Vec<u8>, words: &[u32]| {
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    };
    let mut bytes = Vec::new();
    words(&mut bytes, &[u32::from(passcode == 2)]);
    words(&mut bytes, &[7, passcode, 1, 0x58, 1, 3]);
    words(&mut bytes, &[1, passcode, 1, 4, 0x20]);
    words(&mut bytes, &[3, 1, 1, biometry]);
    bytes.resize(bytes.len() + biometry as usize, 0);
    words(&mut bytes, &[15, 1, 1, 0]);
    bytes
}

#[test]
fn the_kernels_initialization_sets_the_logging_level_with_the_head_alone() {
    let mut credentials = Credentials::default();
    let bytes = command_bytes(10, 0x1e, 2, &[]);
    let mut buffers = Buffers {
        input: bytes.clone(),
        output: Vec::new(),
    };
    let answer = request(
        frame(PAYLOAD, 36),
        &mut buffers,
        &mut credentials,
        &mut counter(),
    )
    .unwrap();
    assert_eq!(answer, reply(frame(PAYLOAD, 36), 12, 0));
    assert_eq!(buffers.output, HEAD);
    // The next context reports that level.
    let (_, output) = ask(&mut credentials, &mut counter(), 1, &501u32.to_le_bytes());
    assert_eq!(output[16], 0x1e);
}

#[test]
fn lockdown_mode_reads_as_off_and_other_variables_refuse() {
    let mut credentials = Credentials::default();
    assert_eq!(
        ask(&mut credentials, &mut counter(), 25, &41u32.to_le_bytes()),
        (0, alloc::vec![0])
    );
    refused(&mut credentials, 25, &2u32.to_le_bytes());
}

#[test]
fn the_engines_initial_variables_read_as_it_sets_them() {
    let mut credentials = Credentials::default();
    for (variable, value) in [(5u32, 0u8), (6, 0), (7, 0), (26, 0), (33, 1), (34, 0)] {
        assert_eq!(
            ask(
                &mut credentials,
                &mut counter(),
                25,
                &variable.to_le_bytes()
            ),
            (0, alloc::vec![value]),
            "variable {variable}"
        );
    }
    // Bytes after the variable are not read.
    let mut long = 7u32.to_le_bytes().to_vec();
    long.extend_from_slice(&[0xaa; 4]);
    assert_eq!(
        ask(&mut credentials, &mut counter(), 25, &long),
        (0, alloc::vec![0])
    );
    // No input, and less than the variable.
    assert_eq!(
        ask(&mut credentials, &mut counter(), 25, &[]),
        (BAD_PARAMETER, Vec::new())
    );
    assert_eq!(
        ask(&mut credentials, &mut counter(), 25, &[7, 0]),
        (-5i32 as u32, Vec::new())
    );
    // Variables set later, or by data providers (69, the context pool's
    // statistics), are named once each.
    refused(&mut credentials, 25, &16u32.to_le_bytes());
    refused(&mut credentials, 25, &69u32.to_le_bytes());
    refused(&mut credentials, 25, &69u32.to_le_bytes());
    let notes: Vec<_> = credentials.diagnostics().collect();
    assert_eq!(
        notes,
        [
            "SEP credential manager: environment variable 16 is not modeled",
            "SEP credential manager: environment variable 69 is not modeled",
        ]
    );
}

#[test]
fn biometric_policies_are_never_satisfied_without_biometry() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (handle, _) = create(&mut credentials, &mut entropy);
    // The lone biometry leaf as allocated: type 3, state 1, +8 1 and the
    // data size of the version, its bytes zero.
    let leaf = |data: u32| {
        let mut bytes = 0u32.to_le_bytes().to_vec();
        for word in [3u32, 1, 1, data] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.resize(bytes.len() + data as usize, 0);
        bytes
    };
    for policy in [
        &b"HumanPresence"[..],
        b"UserIdentificationWithBiometrics",
        b"DeviceOwnerAuthenticationWithBiometrics",
    ] {
        assert_eq!(
            ask(
                &mut credentials,
                &mut entropy,
                3,
                &verify_policy(&handle, policy, true)
            ),
            (0, leaf(0xdd))
        );
    }
    // A validated passcode does not satisfy biometry.
    credentials.passcode_validated(&handle).unwrap();
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&handle, b"DeviceOwnerAuthenticationWithBiometrics", false)
        ),
        (0, leaf(0xdd))
    );
    assert_eq!(
        ask_version(
            &mut credentials,
            &mut entropy,
            3,
            1,
            &verify_policy(&handle, b"UserIdentificationWithBiometrics", false)
        ),
        (0, leaf(0x9c))
    );
    // An unknown context is still ACM's own answer.
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&[9; 16], b"HumanPresence", true)
        ),
        (NO_CONTEXT, Vec::new())
    );
    assert!(credentials.diagnostics().next().is_none());
}

#[test]
fn the_supported_version_is_two_for_exactly_one_byte() {
    let mut credentials = Credentials::default();
    assert_eq!(
        ask(&mut credentials, &mut counter(), 22, &[2]),
        (0, alloc::vec![2])
    );
    assert_eq!(
        ask(&mut credentials, &mut counter(), 22, &[]),
        (BAD_PARAMETER, Vec::new())
    );
    assert_eq!(
        ask(&mut credentials, &mut counter(), 22, &[2, 2]),
        (BAD_PARAMETER, Vec::new())
    );
}

#[test]
fn contexts_get_random_handles_the_logging_level_and_tracking_numbers() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (status, output) = ask(&mut credentials, &mut entropy, 36, &501u32.to_le_bytes());
    assert_eq!(status, 0);
    let mut expected: Vec<u8> = (1..=16).collect();
    expected.push(0x28);
    expected.extend_from_slice(&100u32.to_le_bytes());
    assert_eq!(output, expected);
    // Command 1 stops after the level; 52 tracks like 36.
    let (_, output) = ask(&mut credentials, &mut entropy, 1, &(-1i32).to_le_bytes());
    assert_eq!(
        output,
        [(17..=32).collect::<Vec<u8>>(), alloc::vec![0x28]].concat()
    );
    let (_, output) = ask(&mut credentials, &mut entropy, 52, &501u32.to_le_bytes());
    assert_eq!(output[17..], 102u32.to_le_bytes());
    assert_eq!(credentials.contexts(), 3);
    for input in [&[][..], &[1, 2, 3], &[0; 5]] {
        assert_eq!(
            ask(&mut credentials, &mut entropy, 36, input),
            (BAD_PARAMETER, Vec::new())
        );
    }
    assert_eq!(credentials.contexts(), 3);
}

#[test]
fn a_null_global_or_used_handle_is_drawn_again() {
    let mut credentials = Credentials::default();
    let mut draws = [[0u8; 16], [0xff; 16], [7; 16], [7; 16], [8; 16]].into_iter();
    let mut entropy = move |bytes: &mut [u8]| {
        bytes.copy_from_slice(&draws.next().unwrap());
        Ok(())
    };
    assert_eq!(create(&mut credentials, &mut entropy).0, [7; 16]);
    assert_eq!(create(&mut credentials, &mut entropy).0, [8; 16]);
}

#[test]
fn a_handle_exists_only_once_externalized_and_until_deleted() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (handle, tracking) = create(&mut credentials, &mut entropy);
    assert_eq!(
        ask(&mut credentials, &mut entropy, 37, &handle),
        (NOT_EXTERNALIZED, Vec::new())
    );
    assert_eq!(
        ask(&mut credentials, &mut entropy, 19, &handle),
        (0, Vec::new())
    );
    let mut exists = alloc::vec![1, 0, 0, 0, 0];
    assert_eq!(
        ask(&mut credentials, &mut entropy, 18, &handle),
        (0, exists.clone())
    );
    exists.extend_from_slice(&tracking.to_le_bytes());
    assert_eq!(
        ask(&mut credentials, &mut entropy, 37, &handle),
        (0, exists)
    );
    assert_eq!(
        ask(&mut credentials, &mut entropy, 2, &handle),
        (0, Vec::new())
    );
    for command in [2, 18, 19, 37] {
        assert_eq!(
            ask(&mut credentials, &mut entropy, command, &handle),
            (NO_CONTEXT, Vec::new())
        );
    }
    for command in [2, 19] {
        for bad in [[0u8; 16], [0xff; 16]] {
            assert_eq!(
                ask(&mut credentials, &mut entropy, command, &bad),
                (BAD_PARAMETER, Vec::new())
            );
        }
        assert_eq!(
            ask(&mut credentials, &mut entropy, command, &handle[..15]),
            (BAD_PARAMETER, Vec::new())
        );
    }
}

#[test]
fn a_passphrase_is_added_queried_and_removed_in_its_context_only() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (first, _) = create(&mut credentials, &mut entropy);
    let (second, _) = create(&mut credentials, &mut entropy);
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            5,
            &add_passphrase(&first, b"pw", 1)
        ),
        (0, Vec::new())
    );
    let contains = |credentials: &mut Credentials, handle: &Handle, kind| {
        ask(
            credentials,
            &mut counter(),
            4,
            &type_and_scope(handle, kind, 1),
        )
    };
    assert_eq!(
        contains(&mut credentials, &first, 2),
        (0, 1u32.to_le_bytes().to_vec())
    );
    assert_eq!(
        contains(&mut credentials, &first, 1),
        (0, 0u32.to_le_bytes().to_vec())
    );
    assert_eq!(
        contains(&mut credentials, &second, 2),
        (0, 0u32.to_le_bytes().to_vec())
    );
    assert_eq!(credentials.passphrase(&first).unwrap().as_slice(), b"pw");
    assert!(credentials.passphrase(&second).is_err());
    // The newest passphrase is the one the keystore reads.
    ask(
        &mut credentials,
        &mut entropy,
        5,
        &add_passphrase(&first, b"newer", 1),
    );
    assert_eq!(credentials.passphrase(&first).unwrap().as_slice(), b"newer");
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            9,
            &type_and_scope(&first, 2, 1)
        ),
        (0, Vec::new())
    );
    assert_eq!(
        contains(&mut credentials, &first, 2),
        (0, 0u32.to_le_bytes().to_vec())
    );
    // Malformed requests and unknown contexts.
    let mut long = add_passphrase(&first, b"", 1);
    long[16 + 32 + 4..16 + 32 + 8].copy_from_slice(&0x81u32.to_le_bytes());
    let mut short = add_passphrase(&first, b"x", 1);
    short.truncate(0x33);
    let mut wrong_length = add_passphrase(&first, b"x", 1);
    wrong_length[16 + 0x1c..16 + 0x20].copy_from_slice(&0x84u32.to_le_bytes());
    let mut domain = add_passphrase(&first, b"x", 1);
    domain[16 + 4] = 4;
    for input in [long, short, wrong_length, domain] {
        assert_eq!(
            ask(&mut credentials, &mut entropy, 5, &input),
            (BAD_PARAMETER, Vec::new())
        );
    }
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            5,
            &add_passphrase(&[9; 16], b"x", 1)
        ),
        (NO_CONTEXT, Vec::new())
    );
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            4,
            &type_and_scope(&first, 2, 1)[..23]
        ),
        (BAD_PARAMETER, Vec::new())
    );
}

#[test]
fn no_client_adds_a_passcode_credential_or_reaches_the_global_set() {
    let mut credentials = Credentials::default();
    let (handle, _) = create(&mut credentials, &mut counter());
    let mut passcode = add_passphrase(&handle, b"", 1);
    passcode[16..20].copy_from_slice(&1u32.to_le_bytes());
    passcode[16 + 0x1c..16 + 0x20].copy_from_slice(&0x1cu32.to_le_bytes());
    refused(&mut credentials, 5, &passcode);
    refused(&mut credentials, 5, &add_passphrase(&handle, b"x", 2));
    refused(&mut credentials, 4, &type_and_scope(&handle, 2, 2));
    refused(&mut credentials, 9, &type_and_scope(&handle, 1, 3));
    let notes: Vec<_> = credentials.diagnostics().collect();
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(notes[0].contains("credential type 1"), "{notes:?}");
}

#[test]
fn device_owner_policy_is_satisfied_only_after_the_passcode_is_validated() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (handle, _) = create(&mut credentials, &mut entropy);
    for policy in [
        &b"DeviceOwnerAuthentication"[..],
        b"DeviceAdminAuthentication",
        b"UserPresence",
    ] {
        assert_eq!(
            ask(
                &mut credentials,
                &mut entropy,
                3,
                &verify_policy(&handle, policy, false)
            ),
            (0, device_owner_reply(1, 0xdd))
        );
    }
    // A passphrase alone satisfies nothing.
    ask(
        &mut credentials,
        &mut entropy,
        5,
        &add_passphrase(&handle, b"pw", 1),
    );
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&handle, b"DeviceOwner", true)
        ),
        (0, device_owner_reply(1, 0xdd))
    );
    credentials.passcode_validated(&handle).unwrap();
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&handle, b"DeviceOwnerAuthentication", false)
        ),
        (0, device_owner_reply(2, 0xdd))
    );
    // Below version 2 the biometry data has the table's size.
    assert_eq!(
        ask_version(
            &mut credentials,
            &mut entropy,
            3,
            1,
            &verify_policy(&handle, b"DeviceOwner", true)
        ),
        (0, device_owner_reply(2, 0x9c))
    );
    // Removing the credential takes the authorization away.
    ask(
        &mut credentials,
        &mut entropy,
        9,
        &type_and_scope(&handle, 1, 1),
    );
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&handle, b"DeviceOwner", false)
        ),
        (0, device_owner_reply(1, 0xdd))
    );
}

#[test]
fn policy_requests_follow_the_recovered_layout() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (handle, _) = create(&mut credentials, &mut entropy);
    let good = verify_policy(&handle, b"DeviceOwner", false);
    // Every prefix that cuts the name, its NUL, preflight or the age fails.
    for end in 0..good.len() {
        assert_eq!(
            ask(&mut credentials, &mut entropy, 3, &good[..end]).0,
            BAD_PARAMETER,
            "prefix {end}"
        );
    }
    // Parameters: a count, then type, length and bytes each.
    let mut with = good.clone();
    with.extend_from_slice(&1u32.to_le_bytes());
    with.extend_from_slice(&5u32.to_le_bytes());
    with.extend_from_slice(&2u32.to_le_bytes());
    with.extend_from_slice(&[1, 2]);
    assert_eq!(ask(&mut credentials, &mut entropy, 3, &with).0, 0);
    let notes: Vec<_> = credentials.diagnostics().collect();
    assert!(
        notes.iter().any(|n| n.contains("ACL parameters")),
        "{notes:?}"
    );
    with.pop();
    assert_eq!(
        ask(&mut credentials, &mut entropy, 3, &with).0,
        BAD_PARAMETER
    );
    let mut many = good.clone();
    many.extend_from_slice(&11u32.to_le_bytes());
    assert_eq!(
        ask(&mut credentials, &mut entropy, 3, &many).0,
        BAD_PARAMETER
    );
    let mut name = handle.to_vec();
    name.extend_from_slice(&[b'A'; 0x81]);
    name.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    assert_eq!(
        ask(&mut credentials, &mut entropy, 3, &name).0,
        BAD_PARAMETER
    );
    assert_eq!(
        ask(
            &mut credentials,
            &mut entropy,
            3,
            &verify_policy(&[9; 16], b"DeviceOwner", false)
        ),
        (NO_CONTEXT, Vec::new())
    );
    refused(
        &mut credentials,
        3,
        &verify_policy(&handle, b"BootPolicy", false),
    );
    refused(
        &mut credentials,
        3,
        &verify_policy(&handle, b"BootPolicy", false),
    );
    let notes: Vec<_> = credentials.diagnostics().collect();
    assert_eq!(notes.len(), 1, "{notes:?}");
}

#[test]
fn contexts_are_independent_and_the_pool_keeps_acms_bounds() {
    let mut credentials = Credentials::default();
    let mut entropy = counter();
    let (first, _) = create(&mut credentials, &mut entropy);
    let (second, _) = create(&mut credentials, &mut entropy);
    credentials.passcode_validated(&first).unwrap();
    let policy = |credentials: &mut Credentials, handle: &Handle| {
        ask(
            credentials,
            &mut counter(),
            3,
            &verify_policy(handle, b"DeviceOwner", true),
        )
        .1[0]
    };
    assert_eq!(
        (
            policy(&mut credentials, &first),
            policy(&mut credentials, &second)
        ),
        (1, 0)
    );
    ask(&mut credentials, &mut entropy, 2, &first);
    assert!(credentials.passcode_validated(&first).is_err());
    assert_eq!(policy(&mut credentials, &second), 0);

    // 0xc0 non-auto-disposable contexts at most.
    let mut credentials = Credentials::default();
    let mut next = 0u32;
    let mut entropy = move |bytes: &mut [u8]| {
        next += 1;
        bytes.fill(0);
        bytes[..4].copy_from_slice(&next.to_le_bytes());
        Ok(())
    };
    for _ in 0..0xc0 {
        assert_eq!(ask(&mut credentials, &mut entropy, 52, &[0; 4]).0, 0);
    }
    assert_eq!(
        ask(&mut credentials, &mut entropy, 52, &[0; 4]),
        (POOL_FULL, Vec::new())
    );
    // At 0x100 the least recently used auto-disposable context gives way.
    let (oldest, _) = create(&mut credentials, &mut entropy);
    let (older, _) = create(&mut credentials, &mut entropy);
    for _ in 0..0x3e {
        create(&mut credentials, &mut entropy);
    }
    assert_eq!(credentials.contexts(), 0x100);
    ask(&mut credentials, &mut entropy, 19, &oldest);
    let (newest, _) = create(&mut credentials, &mut entropy);
    assert_eq!(credentials.contexts(), 0x100);
    assert!(credentials.exists(&oldest) && credentials.exists(&newest));
    assert!(!credentials.exists(&older));
}

#[test]
fn foreign_magic_other_requests_and_lengths_are_refused() {
    let mut credentials = Credentials::default();
    let mut bytes = command_bytes(22, 0, 2, &[2]);
    bytes[28] = 0;
    let mut buffers = Buffers {
        input: bytes,
        output: Vec::new(),
    };
    let answer = request(
        frame(PAYLOAD, 37),
        &mut buffers,
        &mut credentials,
        &mut counter(),
    )
    .unwrap_err()
    .answer
    .unwrap();
    assert_eq!(answer.output, HEAD);
    assert_eq!(answer.frame.data, UNSUPPORTED);
    for (tag, length) in [(1, 37), (PAYLOAD, 35), (PAYLOAD, 0x4001)] {
        let mut buffers = Buffers {
            input: alloc::vec![0; 0x4001],
            output: Vec::new(),
        };
        let answer = request(
            frame(tag, length),
            &mut buffers,
            &mut credentials,
            &mut counter(),
        )
        .unwrap_err()
        .answer
        .unwrap();
        assert!(answer.output.is_empty());
        assert_eq!(answer.frame, failure(frame(tag, length)));
    }
}

#[test]
fn an_unimplemented_command_is_refused_and_named_once() {
    let mut credentials = Credentials::default();
    refused(&mut credentials, 46, &[0; 16]);
    refused(&mut credentials, 46, &[0; 16]);
    let notes: Vec<_> = credentials.diagnostics().collect();
    assert_eq!(
        notes,
        ["SEP credential manager: command 46 is not implemented"]
    );
}

#[test]
fn the_service_is_the_kernels_endpoint_with_its_16_kib_buffers() {
    let scrd = service();
    assert_eq!(scrd.id, 10);
    assert!(scrd.accepts(true, 0x4000, 0x4000));
    assert!(scrd.accepts(false, 0x4000, 0x4000));
    assert!(!scrd.accepts(true, 0x8000, 0x4000));
}
