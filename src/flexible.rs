// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};

use crate::OsRotError;
use crate::ffi::{OsRotCerts, OsRotLog, OsRotMeasurement};

/// Upper bound on the trailing array we'll allocate for.
const MAX_FLEXIBLE_BYTES: usize = 16 * 1024 * 1024;

/// This trait is meant to be implemented for a C structure that contains a
/// count field and ends with a flexible array member like so:
///
/// ```c
/// struct {
///     uint32_t count;
///     Item items[];
/// }
/// ```
///
/// Once implemented, users can call [`alloc_flexible_struct`] to get back a
/// `Box<Self>` that contains the count header followed by a trailing
/// `[Self::Item]` array (a dynamically-sized type) sized for the supplied
/// `capacity`.
///
/// # Safety
///
/// Implementers must guarantee that:
///
/// - `Self` is a `#[repr(C)]` DST whose only unsized field is a trailing
///   `[Self::Item]` prefixed by a `u32` count at offset 0, the field that
///   [`alloc_flexible_struct`] writes `capacity` into. Its layout must match
///   `Layout::new::<u32>().extend(Layout::array::<Self::Item>(n)).pad_to_align()`
///   for every `n`, so the `Box`'s drop frees the same layout that was
///   allocated.
/// - [`Self::from_slice_ptr`] reinterprets the input pointer as `Self`. Both
///   pointers are "fat pointers" that contain an address and length so rust
///   allows us to "cast" between them, however attempting to use one type as
///   the other would be undefined behavior. This "fat pointer"/layout is used
///   by `Box` and its drop method. To better visualize this layout consider the
///   following:
///
/// ```text
///  *mut [Self::Item]
///     ┌── fat pointer ─┐
///  ┌───────────┬──────────────┐
///  │ data_ptr  │  len: usize  │
///  └───────────┴──────────────┘
///          │
///          ▼
///          ┌──────────┬──────────┬── ... ──┬─────────────┐
///          │  Item[0] │  Item[1] │         │ Item[len-1] │
///          └──────────┴──────────┴── ... ──┴─────────────┘
///
///     │
///     │ `p as *mut Self` cast
///     ▼
///
///  *mut Self
///     ┌── fat pointer ─┐
///  ┌───────────┬──────────────┐
///  │ data_ptr  │  len: usize  │
///  └───────────┴──────────────┘
///          │
///          ▼
///          ┌─────────────────────┬─────────┬─────────┬─ ... ─┬─────────────┐
///          │         u32         │ Item[0] │ Item[1] │       │ Item[len-1] │
///          └─────────────────────┴─────────┴─────────┴─ ... ─┴─────────────┘
///          └──size_of::<u32>()──┘└──────── len * size_of::<Item>() ────────┘
/// ```
pub(crate) unsafe trait FlexibleArrayMember {
    /// Element type of the trailing flexible array member.
    type Item;

    /// Reinterpret a slice pointer as a pointer to `Self`, preserving its
    /// address and length metadata.
    fn from_slice_ptr(p: *mut [Self::Item]) -> *mut Self;
}

pub(crate) fn alloc_flexible_struct<D>(
    capacity: u32,
) -> Result<Box<D>, OsRotError>
where
    D: FlexibleArrayMember + ?Sized,
{
    let array = Layout::array::<D::Item>(capacity as usize)
        .map_err(|_| OsRotError::LayoutOverflow)?;
    if array.size() > MAX_FLEXIBLE_BYTES {
        return Err(OsRotError::TooLarge { requested: array.size() });
    }
    let (layout, _) = Layout::new::<u32>()
        .extend(array)
        .map_err(|_| OsRotError::LayoutOverflow)?;
    let layout = layout.pad_to_align();

    // SAFETY: layout.size() >= 4 (u32 header always present).
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }

    // SAFETY: trait contract puts the u32 count at offset 0.
    unsafe {
        (raw as *mut u32).write(capacity);
    }

    let slice_ptr = std::ptr::slice_from_raw_parts_mut(
        raw as *mut D::Item,
        capacity as usize,
    );
    let dst_ptr = D::from_slice_ptr(slice_ptr);

    // SAFETY: dst_ptr matches the layout Box::drop will compute from
    // the fat pointer's metadata.
    Ok(unsafe { Box::from_raw(dst_ptr) })
}

unsafe impl FlexibleArrayMember for OsRotLog {
    type Item = OsRotMeasurement;

    fn from_slice_ptr(p: *mut [Self::Item]) -> *mut Self {
        p as *mut Self
    }
}

unsafe impl FlexibleArrayMember for OsRotCerts {
    type Item = u8;

    fn from_slice_ptr(p: *mut [Self::Item]) -> *mut Self {
        p as *mut Self
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi::{OS_ROT_HASH_SIZE, OsRotLog, OsRotMeasurement};

    use super::*;

    #[test]
    fn zero_capacity_is_valid() {
        let log: Box<OsRotLog> = alloc_flexible_struct(0).unwrap();
        assert_eq!(log.count, 0);
        assert_eq!(log.measurements.len(), 0);
    }

    #[test]
    fn count_field_set_to_capacity() {
        let log: Box<OsRotLog> = alloc_flexible_struct(42).unwrap();
        assert_eq!(log.count, 42);
        assert_eq!(log.measurements.len(), 42);
    }

    #[test]
    fn tail_is_zeroed_and_writable() {
        let mut log: Box<OsRotLog> = alloc_flexible_struct(3).unwrap();
        for m in &log.measurements {
            assert_eq!(m.hash, [0u8; OS_ROT_HASH_SIZE]);
        }
        log.measurements[1].hash[7] = 0xAB;
        assert_eq!(log.measurements[1].hash[7], 0xAB);
    }

    fn mock_kernel_fill(log: &mut OsRotLog, reported_count: u32) {
        let cap = log.measurements.len();
        log.count = reported_count;
        let to_write = (reported_count as usize).min(cap);
        for i in 0..to_write {
            log.measurements[i].hash =
                [(i as u8).wrapping_add(1); OS_ROT_HASH_SIZE];
        }
    }

    #[test]
    fn kernel_fill_within_capacity_is_sound() {
        let mut log: Box<OsRotLog> = alloc_flexible_struct(4).unwrap();
        mock_kernel_fill(&mut log, 4);

        for (i, m) in log.measurements.iter().enumerate() {
            assert_eq!(m.hash, [(i as u8).wrapping_add(1); OS_ROT_HASH_SIZE]);
        }
    }

    #[test]
    fn layout_matches_c_struct() {
        let items = 5;
        let log: Box<OsRotLog> = alloc_flexible_struct(items).unwrap();
        assert_eq!(
            std::mem::size_of_val(&*log),
            std::mem::size_of::<u32>()
                + (items as usize * std::mem::size_of::<OsRotMeasurement>())
        );

        // The u32 must be at offset 0 (trait contract).
        let base = &*log as *const OsRotLog as *const u8;
        let count = &log.count as *const u32 as *const u8;
        assert_eq!(unsafe { count.offset_from(base) }, 0);

        // The tail must start right after the header (no padding here).
        let tail = log.measurements.as_ptr() as *const u8;
        assert_eq!(unsafe { tail.offset_from(base) }, 4);
    }
}
