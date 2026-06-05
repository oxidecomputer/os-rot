// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::mem::offset_of;

use rustix::ioctl::Opcode;

/// The path to the os_rot device to issue ioctls.
pub const OS_ROT_DEV: &str = "/dev/os_rot";

/// Measurements are assumed to be SHA2-384 digests.
pub const OS_ROT_HASH_SIZE: usize = 48;

/// Attestations are assumed to be 384-bit ECDSA signatures.
pub const OS_ROT_SIG_SIZE: usize = 96;

/// os_rot IOCTLs.
const OS_ROT_IOC: Opcode = ((b'R' as Opcode) << 24)
    | ((b'O' as Opcode) << 16)
    | ((b'T' as Opcode) << 8);

/// A single measurement.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OsRotMeasurement {
    pub hash: [u8; OS_ROT_HASH_SIZE],
}

/// Retrieve the measurement log (os_rot_log_t).
pub const OS_ROT_IOC_GET_LOG: Opcode = OS_ROT_IOC | 0x01;

/// When `count` is 0 on input, the driver returns the current number of
/// recorded measurements in `count` and writes no entries.  Otherwise `count`
/// is taken as the number of entries the caller's trailing `measurements`
/// buffer can hold; on return it is updated to the number actually written.
/// If the buffer is too small, ENOSPC is returned.
#[repr(C)]
pub struct OsRotLog {
    pub count: u32,
    pub measurements: [OsRotMeasurement],
}

/// Retrieve the certificate chain that links our attestation signing keys to
/// a trusted PKI root (os_rot_certs_t).
pub const OS_ROT_IOC_GET_CERTS: Opcode = OS_ROT_IOC | 0x02;

/// When `chain_size` is 0 on input, the driver returns the required size.
/// Otherwise it fills `chain` with the certificate chain data.
#[repr(C)]
pub struct OsRotCerts {
    pub chain_size: u32,
    pub chain: [u8],
}

/// Provides an attestation over the current set of measurements with a given
/// nonce for freshness and returns the resulting signature (os_rot_attest_t).
///
/// The attestation signature is over SHA384(log || nonce), binding the
/// current measurement log to the caller-provided nonce.  This allows a
/// verifier to confirm both the measurements and the freshness of the
/// attestation in a single signature verification.
pub const OS_ROT_IOC_ATTEST: Opcode = OS_ROT_IOC | 0x03;

/// The caller provides `nonce` which the driver combines with the measurement
/// log and signs it to provide an attestation signature.
#[repr(C)]
pub struct OsRotAttest {
    pub nonce: [u8; OS_ROT_HASH_SIZE],
    pub sig: [u8; OS_ROT_SIG_SIZE],
}

// Test the kernel ABI at compile time.
const _: () = {
    assert!(size_of::<OsRotMeasurement>() == OS_ROT_HASH_SIZE);
    assert!(align_of::<OsRotMeasurement>() == 1);

    assert!(size_of::<OsRotAttest>() == OS_ROT_HASH_SIZE + OS_ROT_SIG_SIZE);
    assert!(offset_of!(OsRotAttest, nonce) == 0);
    assert!(offset_of!(OsRotAttest, sig) == OS_ROT_HASH_SIZE);

    // alloc_flexible_struct writes the count at offset 0 of each DST.
    assert!(offset_of!(OsRotLog, count) == 0);
    assert!(offset_of!(OsRotCerts, chain_size) == 0);
};
