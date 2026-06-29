/// Errors produced while parsing or verifying a block-format volume or key-set.
///
/// All variants are `Copy` so the `no_std` read path never allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A slice was shorter than the structure it was expected to contain.
    Truncated,
    /// A region magic number did not match (`BBLK`, `BMFT`, `BSIG`, `BKEY`).
    BadMagic,
    /// `format_version` / schema version is not understood by this build.
    UnsupportedVersion,
    /// The superblock header CRC-32 did not match.
    BadCrc,
    /// `digest_algo` or `sig_algo` is not supported.
    UnsupportedAlgo,
    /// Manifest bytes did not hash to `superblock.manifest_sha256`.
    ManifestHashMismatch,
    /// An item's bytes did not hash to its recorded `content_sha256`.
    ContentHashMismatch,
    /// No trusted signature verified over the signed object.
    SignatureInvalid,
    /// A signature verified but the signer is not in the trust store.
    UntrustedSigner,
    /// Fewer than the required number of distinct root signatures verified.
    QuorumNotMet,
    /// A candidate key-set's version was not strictly greater than the current one.
    KeysetRollback,
    /// More keys/revocations than this build's fixed capacity can hold.
    CapacityExceeded,
    /// The required capability is absent, the key is revoked, or it is outside
    /// its validity window.
    CapabilityDenied,
    /// A CBOR document was malformed.
    Cbor,
    /// A structural invariant was violated (e.g. unaligned offset, overlap).
    Malformed,
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
