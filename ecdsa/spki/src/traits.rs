//! Traits for encoding/decoding SPKI public keys.

use crate::{Error, Result, SubjectPublicKeyInfoRef};

#[cfg(feature = "alloc")]
use der::Document;

#[cfg(feature = "pem")]
use {
    alloc::string::String,
    der::pem::{LineEnding, PemLabel},
};

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(doc)]
use crate::SubjectPublicKeyInfo;

/// Parse a public key object from an encoded SPKI document.
pub trait DecodePublicKey: Sized {
    /// Deserialize object from ASN.1 DER-encoded [`SubjectPublicKeyInfo`]
    /// (binary format).
    fn from_public_key_der(bytes: &[u8]) -> Result<Self>;

    /// Deserialize PEM-encoded [`SubjectPublicKeyInfo`].
    ///
    /// Keys in this format begin with the following delimiter:
    ///
    /// ```text
    /// -----BEGIN PUBLIC KEY-----
    /// ```
    #[cfg(feature = "pem")]
    fn from_public_key_pem(s: &str) -> Result<Self> {
        let (label, doc) = Document::from_pem(s)?;
        SubjectPublicKeyInfoRef::validate_pem_label(label)?;
        Self::from_public_key_der(doc.as_bytes())
    }

    /// Load public key object from an ASN.1 DER-encoded file on the local
    /// filesystem (binary format).
    #[cfg(feature = "std")]
    fn read_public_key_der_file(path: impl AsRef<Path>) -> Result<Self> {
        let doc = Document::read_der_file(path)?;
        Self::from_public_key_der(doc.as_bytes())
    }

    /// Load public key object from a PEM-encoded file on the local filesystem.
    #[cfg(all(feature = "pem", feature = "std"))]
    fn read_public_key_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let (label, doc) = Document::read_pem_file(path)?;
        SubjectPublicKeyInfoRef::validate_pem_label(&label)?;
        Self::from_public_key_der(doc.as_bytes())
    }
}

impl<T> DecodePublicKey for T
where
    T: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = Error>,
{
    fn from_public_key_der(bytes: &[u8]) -> Result<Self> {
        Self::try_from(SubjectPublicKeyInfoRef::try_from(bytes)?)
    }
}

/// Serialize a public key object to a SPKI-encoded document.
#[cfg(feature = "alloc")]
pub trait EncodePublicKey {
    /// Serialize a [`Document`] containing a SPKI-encoded public key.
    fn to_public_key_der(&self) -> Result<Document>;

    /// Serialize this public key as PEM-encoded SPKI with the given [`LineEnding`].
    #[cfg(feature = "pem")]
    fn to_public_key_pem(&self, line_ending: LineEnding) -> Result<String> {
        let doc = self.to_public_key_der()?;
        Ok(doc.to_pem(SubjectPublicKeyInfoRef::PEM_LABEL, line_ending)?)
    }

    /// Write ASN.1 DER-encoded public key to the given path
    #[cfg(feature = "std")]
    fn write_public_key_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        Ok(self.to_public_key_der()?.write_der_file(path)?)
    }

    /// Write ASN.1 DER-encoded public key to the given path
    #[cfg(all(feature = "pem", feature = "std"))]
    fn write_public_key_pem_file(
        &self,
        path: impl AsRef<Path>,
        line_ending: LineEnding,
    ) -> Result<()> {
        let doc = self.to_public_key_der()?;
        Ok(doc.write_pem_file(path, SubjectPublicKeyInfoRef::PEM_LABEL, line_ending)?)
    }
}
