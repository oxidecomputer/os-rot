// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Communication with the helios AMD RoT (PSP).
//!
//! The OS driver makes use of the DICE Protection Environment (DPE) present on
//! the AMD CPU to measure and attest to the phase 1 and 2 images. In the future
//! we may extend that to include zones, processes, VMs, services, etc.

use std::os::fd::OwnedFd;

use rustix::ioctl::ioctl;

use crate::{
    ffi::{
        OS_ROT_HASH_SIZE, OS_ROT_SIG_SIZE, OsRotAttest, OsRotCerts, OsRotLog,
    },
    flexible::alloc_flexible_struct,
    ioctls::{Attest, GetCerts, GetLog},
};

mod ffi;
mod flexible;
mod ioctls;

#[derive(Debug, thiserror::Error)]
pub enum OsRotError {
    #[error("failed to open os_rot device")]
    DevicePath(#[source] std::io::Error),

    #[error("the number of measurement logs changed between ioctl calls")]
    LogSizeChanged,

    #[error("the number of certs changed between ioctl calls")]
    CertSizeChanged,

    #[error("OS_ROT_IOC_GET_LOG ioctl call failed: {errno}")]
    GetLogsIoctl { errno: rustix::io::Errno },

    #[error("OS_ROT_IOC_GET_CERTS ioctl call failed: {errno}")]
    GetCertsIoctl { errno: rustix::io::Errno },

    #[error("OS_ROT_IOC_ATTEST ioctl call failed: {errno}")]
    AttestIoctl { errno: rustix::io::Errno },

    #[error("flexible array layout overflowed")]
    LayoutOverflow,

    #[error("kernel reported an implausibly large size: {requested} bytes")]
    TooLarge { requested: usize },
}

#[derive(Debug)]
pub struct OsRotHandle {
    fd: OwnedFd,
}

impl OsRotHandle {
    pub fn new() -> Result<Self, OsRotError> {
        let dev = std::fs::File::open(ffi::OS_ROT_DEV)
            .map_err(OsRotError::DevicePath)?;

        Ok(Self { fd: dev.into() })
    }

    /// Retrieve the measurement log: the current set of SHA2-384 digests
    /// recorded by the RoT.
    ///
    /// The driver is first queried with a zero-length buffer to learn how many
    /// measurements are currently recorded, then queried again with a buffer
    /// sized to hold exactly that many entries.
    pub fn get_logs(&self) -> Result<Vec<Vec<u8>>, OsRotError> {
        let mut probe: Box<OsRotLog> = alloc_flexible_struct(0)?;

        unsafe {
            ioctl(&self.fd, GetLog(&mut probe))
                .map_err(|e| OsRotError::GetLogsIoctl { errno: e })?;
        }

        // Kernel-reported number of measurement log entries.
        let probe_count = probe.count;
        let mut logs: Box<OsRotLog> = alloc_flexible_struct(probe_count)?;

        match unsafe { ioctl(&self.fd, GetLog(&mut logs)) } {
            Ok(_) => Ok(logs.measurement_hashes()),
            Err(e) if e == rustix::io::Errno::NOSPC => {
                Err(OsRotError::LogSizeChanged)
            }
            Err(e) => Err(OsRotError::GetLogsIoctl { errno: e }),
        }
    }

    /// Retrieve the certificate chain that links the RoT's attestation signing
    /// keys to a trusted PKI root.
    ///
    /// The driver is first queried with a zero-length buffer to learn the
    /// required chain size, then queried again with a buffer of that size to
    /// receive the chain data.
    pub fn get_certs(&self) -> Result<Vec<u8>, OsRotError> {
        let mut probe: Box<OsRotCerts> = alloc_flexible_struct(0)?;

        unsafe {
            ioctl(&self.fd, GetCerts(&mut probe))
                .map_err(|e| OsRotError::GetCertsIoctl { errno: e })?;
        }

        // Kernel-reported certificate chain size, in bytes.
        let probe_chain_size = probe.chain_size;
        let mut certs: Box<OsRotCerts> =
            alloc_flexible_struct(probe_chain_size)?;

        match unsafe { ioctl(&self.fd, GetCerts(&mut certs)) } {
            Ok(_) => Ok(certs.chain_bytes()),
            Err(e) if e == rustix::io::Errno::NOSPC => {
                Err(OsRotError::CertSizeChanged)
            }
            Err(e) => Err(OsRotError::GetCertsIoctl { errno: e }),
        }
    }

    /// Attest over the current measurement log, binding it to `nonce` for
    /// freshness, and return the resulting signature.
    ///
    /// The driver signs `SHA384(log || nonce)`, so the returned signature lets
    /// a verifier confirm both the measurements and the freshness of the
    /// attestation in a single verification.
    pub fn attest(
        &self,
        nonce: &[u8; OS_ROT_HASH_SIZE],
    ) -> Result<Vec<u8>, OsRotError> {
        let mut attest =
            OsRotAttest { nonce: *nonce, sig: [0u8; OS_ROT_SIG_SIZE] };

        match unsafe { ioctl(&self.fd, Attest(&mut attest)) } {
            Ok(_) => Ok(attest.sig.to_vec()),
            Err(e) => Err(OsRotError::AttestIoctl { errno: e }),
        }
    }
}

impl OsRotLog {
    /// Collect the measurement hashes the driver wrote into this buffer.
    fn measurement_hashes(&self) -> Vec<Vec<u8>> {
        let capacity = self.measurements.len();
        let num_items = usize::try_from(self.count)
            .expect("usize is at least 32 bits wide");
        assert!(num_items <= capacity,);

        self.measurements[..num_items]
            .iter()
            .map(|m| Vec::from(m.hash))
            .collect()
    }
}

impl OsRotCerts {
    /// Copy out the certificate chain bytes the driver wrote into this buffer.
    fn chain_bytes(&self) -> Vec<u8> {
        let capacity = self.chain.len();
        let num_items = usize::try_from(self.chain_size)
            .expect("usize is at least 32 bits wide");
        assert!(num_items <= capacity,);

        self.chain[..num_items].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi::{OS_ROT_HASH_SIZE, OsRotCerts, OsRotLog};
    use crate::flexible::alloc_flexible_struct;

    fn fill_log(capacity: u32, reported: u32) -> Box<OsRotLog> {
        let mut log: Box<OsRotLog> = alloc_flexible_struct(capacity).unwrap();
        log.count = reported;
        let n = (reported as usize).min(log.measurements.len());
        for i in 0..n {
            log.measurements[i].hash = [i as u8 + 1; OS_ROT_HASH_SIZE];
        }
        log
    }

    #[test]
    fn measurement_hashes_returns_reported_entries() {
        // Kernel filled 3 of the 4 slots we allocated.
        let log = fill_log(4, 3);
        let hashes = log.measurement_hashes();
        assert_eq!(hashes.len(), 3);
        for (i, h) in hashes.iter().enumerate() {
            assert_eq!(h.as_slice(), [i as u8 + 1; OS_ROT_HASH_SIZE]);
        }
    }

    #[test]
    fn measurement_hashes_empty_log() {
        let log = fill_log(0, 0);
        assert!(log.measurement_hashes().is_empty());
    }

    #[test]
    #[should_panic]
    fn measurement_hashes_over_report_aborts() {
        // Simulate the kernel filling in 2 slots but saying there are 3
        // available.
        let log = fill_log(2, 3);
        let _ = log.measurement_hashes();
    }

    #[test]
    fn chain_bytes_returns_reported_prefix() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(8).unwrap();
        certs.chain_size = 3;
        certs.chain[..3].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(certs.chain_bytes(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    #[should_panic]
    fn chain_bytes_over_report_aborts() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(2).unwrap();
        // Simulate the kernel filling in 2 slots but saying there are 3
        // available.
        certs.chain_size = 3;
        let _ = certs.chain_bytes();
    }
}
