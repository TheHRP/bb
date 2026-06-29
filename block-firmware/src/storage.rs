//! Block storage abstraction.
//!
//! The node logic is written against this trait so it is identical on the
//! ESP32 (SD over SDMMC/SPI) and on a host (an in-memory slice, or a file). The
//! firmware binary provides the device implementation; tests use [`SliceStorage`].

/// Errors a storage backend may raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// A read/write fell outside the medium.
    OutOfBounds,
    /// A backend I/O failure.
    Io,
}

/// Random-access block medium holding a volume image.
///
/// Offsets and lengths are byte values; implementations may require block
/// alignment internally but must present a byte-addressable view.
pub trait Storage {
    /// Total medium size in bytes (the volume's `volume_capacity`).
    fn size(&self) -> u64;

    /// Read exactly `buf.len()` bytes starting at `offset`.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), StorageError>;

    /// Write `data` starting at `offset`.
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), StorageError>;
}

/// In-memory storage over a mutable byte slice. Used for host tests and for
/// volumes mapped entirely into RAM/PSRAM.
pub struct SliceStorage<'a> {
    data: &'a mut [u8],
}

impl<'a> SliceStorage<'a> {
    pub fn new(data: &'a mut [u8]) -> SliceStorage<'a> {
        SliceStorage { data }
    }
}

impl Storage for SliceStorage<'_> {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let off: usize = offset.try_into().map_err(|_| StorageError::OutOfBounds)?;
        let end = off
            .checked_add(buf.len())
            .ok_or(StorageError::OutOfBounds)?;
        let src = self.data.get(off..end).ok_or(StorageError::OutOfBounds)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), StorageError> {
        let off: usize = offset.try_into().map_err(|_| StorageError::OutOfBounds)?;
        let end = off
            .checked_add(data.len())
            .ok_or(StorageError::OutOfBounds)?;
        let dst = self
            .data
            .get_mut(off..end)
            .ok_or(StorageError::OutOfBounds)?;
        dst.copy_from_slice(data);
        Ok(())
    }
}
