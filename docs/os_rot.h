/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2026 Oxide Computer Company
 */
#ifndef _OS_ROT_H
#define	_OS_ROT_H
/*
 * Oxide OS RoT Driver Interface
 *
 * This driver makes use of the DICE Protection Environment (DPE) present on
 * the AMD CPU to measure and attest to the phase 1 and 2 images.  In the future
 * we may extend that to include zones, processes, VMs, services, etc.
 */
#include <sys/stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/*
 * The path to the os_rot device to issue ioctls.
 */
#define	OS_ROT_DEV		"/dev/os_rot"
/*
 * os_rot IOCTLs.
 */
#define	OS_ROT_IOC		(('R' << 24) | ('O' << 16) | ('T' << 8))
/*
 * Measurements are assumed to be SHA2-384 digests.
 */
#define	OS_ROT_HASH_SIZE	48
/*
 * Attestations are assumed to be 384-bit ECDSA signatures.
 */
#define	OS_ROT_SIG_SIZE		96
/*
 * A single measurement.
 */
typedef struct os_rot_measurement {
	uint8_t		osrm_hash[OS_ROT_HASH_SIZE];
} os_rot_measurement_t;
/*
 * Retrieve the measurement log (os_rot_log_t).
 */
#define	OS_ROT_IOC_GET_LOG	(OS_ROT_IOC | 0x01)
/*
 * When `osrl_count` is 0 on input, the driver returns the current number of
 * recorded measurements in `osrl_count` and writes no entries.  Otherwise
 * `osrl_count` is taken as the number of entries the caller's trailing
 * `osrl_measurements` buffer can hold; on return it is updated to the
 * number actually written.  If the buffer is too small, ENOSPC is
 * returned.
 */
typedef struct os_rot_log {
	uint32_t		osrl_count;
	os_rot_measurement_t	osrl_measurements[];
} os_rot_log_t;
/*
 * Retrieve the certificate chain that links our attestation signing keys to
 * a trusted PKI root (os_rot_certs_t).
 */
#define	OS_ROT_IOC_GET_CERTS	(OS_ROT_IOC | 0x02)
/*
 * When `osrc_chain_size` is 0 on input, the driver returns the required size.
 * Otherwise it fills `osrc_chain` with the certificate chain data.
 */
typedef struct os_rot_certs {
	uint32_t	osrc_chain_size;
	uint8_t		osrc_chain[];
} os_rot_certs_t;
/*
 * Provides an attestation over the current set of measurements with a given
 * nonce for freshness and returns the resulting signature (os_rot_attest_t).
 *
 * The attestation signature is over SHA384(log || nonce), binding the
 * current measurement log to the caller-provided nonce.  This allows a
 * verifier to confirm both the measurements and the freshness of the
 * attestation in a single signature verification.
 */
#define	OS_ROT_IOC_ATTEST	(OS_ROT_IOC | 0x03)
/*
 * The caller provides `osra_nonce` which the driver combines with the
 * measurement log and signs it to provide an attestation signature.
 */
typedef struct os_rot_attest {
	uint8_t		osra_nonce[OS_ROT_HASH_SIZE];
	uint8_t		osra_sig[OS_ROT_SIG_SIZE];
} os_rot_attest_t;
#ifdef __cplusplus
}
#endif
#endif /* _OS_ROT_H */
