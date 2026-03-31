// Copyright 2025 Snowflake Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use aead::{OsRng, rand_core::RngCore as _};
use hmac::{Hmac, Mac};
use sha2::Sha384;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error, Result,
    constants::{
        DEFAULT_FLOE_IV_LENGTH, ENCODED_SPEC_LENGTH, HEADER_TAG_LENGTH,
        SEGMENT_LENGTH_PREFIX_LENGTH,
    },
};

/// Standard parameters with: [FloeAead::AesGcm256], [FloeKdf::HkdfExpandSha384], 32 byte FLOE IV, 4KB encrypted segment length
pub const GCM256_IV256_4K: FloeParameterSpec = FloeParameterSpec {
    aead: FloeAead::AesGcm256,
    hash: FloeKdf::HkdfExpandSha384,
    encrypted_segment_length: 4 * 1024,
    iv_length: DEFAULT_FLOE_IV_LENGTH,
    override_rotation_mask: None,
};

/// Standard parameters with: [FloeAead::AesGcm256], [FloeKdf::HkdfExpandSha384], 32 byte FLOE IV, 1MB encrypted segment length
pub const GCM256_IV256_1M: FloeParameterSpec = FloeParameterSpec {
    aead: FloeAead::AesGcm256,
    hash: FloeKdf::HkdfExpandSha384,
    encrypted_segment_length: 1024 * 1024,
    iv_length: DEFAULT_FLOE_IV_LENGTH,
    override_rotation_mask: None,
};

/// Standard parameters with: [FloeAead::AesGcm256], [FloeKdf::HkdfExpandSha384], 32 byte FLOE IV, 16MB encrypted segment length
pub const GCM256_IV256_16M: FloeParameterSpec = FloeParameterSpec {
    aead: FloeAead::AesGcm256,
    hash: FloeKdf::HkdfExpandSha384,
    encrypted_segment_length: 16 * 1024 * 1024,
    iv_length: DEFAULT_FLOE_IV_LENGTH,
    override_rotation_mask: None,
};

/// AEAD used by FLOE to encrypt each segment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloeAead {
    /// AES GCM with a 256 bit key, 96 bit random nonce, and 128 bit tag
    AesGcm256,
}

/// KDF used within FLOE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloeKdf {
    HkdfExpandSha384,
}

/// Parameters which define a specific use of FLOE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloeParameterSpec {
    aead: FloeAead,
    hash: FloeKdf,
    encrypted_segment_length: usize,
    iv_length: usize,
    override_rotation_mask: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum FloePurpose {
    HeaderTag,
    MessageKey,
    SegmentKey { encoded_segment: [u8; 12] },
}

impl FloePurpose {
    pub(crate) fn from_segment(segment: u64) -> Self {
        let mut encoded_segment = [0u8; 12];

        encoded_segment[..4].copy_from_slice(b"DEK:");
        encoded_segment[4..].copy_from_slice(&segment.to_be_bytes());

        Self::SegmentKey { encoded_segment }
    }

    /// Convert this [`FloePurpose`] enum variant into a byte array.
    ///
    /// This representation can be used inside of the [`FloeKey::derive_key()`] method.
    fn as_bytes(&self) -> &[u8] {
        match self {
            FloePurpose::HeaderTag => b"HEADER_TAG:",
            FloePurpose::MessageKey => b"MESSAGE_KEY:",
            FloePurpose::SegmentKey { encoded_segment } => encoded_segment.as_slice(),
        }
    }
}

/**
 * Represents a key for use with FLOE.
 * Also includes the parameters because a single key should not be used with different sets of parameters.
 * It is explicitly allowed for multiple segment lengths to be allowed with a single key.
 */
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FloeKey {
    pub(crate) key: Vec<u8>,
    #[zeroize(skip)]
    params: FloeParameterSpec,
}

impl FloeKey {
    /// Create a FloeKey from raw key bytes and parameters
    pub fn new(key: &[u8], params: FloeParameterSpec) -> Result<Self> {
        if key.len() != params.get_aead().get_key_length() {
            println!(
                "Key length {} expected {}",
                key.len(),
                params.get_aead().get_key_length()
            );
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            key: key.to_owned(),
            params,
        })
    }

    /// Generate a new random key appropriate for the given parameters
    pub fn new_random(params: FloeParameterSpec) -> Result<Self> {
        let mut key = vec![0u8; params.get_aead().get_key_length()];
        OsRng.fill_bytes(&mut key);
        Ok(Self { key, params })
    }

    /// Returns the raw cryptographic key.
    /// 
    /// <div class="warning">This is a sensitive cryptographic key which should only be handled with great care.</div>
    pub fn get_raw_key(&self) -> &[u8] {
        &self.key
    }

    pub fn get_parameters(&self) -> FloeParameterSpec {
        self.params
    }

    /// Derive a new [`FloeKey`] from this root key.
    ///
    /// This function is a combination of the `FLOE_KDF` and `DERIVE_KEY` internal functions from
    /// the [spec].
    ///
    /// Since the [`FloePurpose`] enum is used to encode the purpose of this KDF operation,
    /// including the case where we create a segment key with a given position, having separate `FLOE_KDF`
    /// and `DERIVE_KEY` functions isn't needed.
    ///
    /// [spec]: https://github.com/C2SP/C2SP/blob/main/FLOE.md#internal-functions
    pub(crate) fn derive_key(
        &self,
        iv: &[u8],
        aad: &[u8],
        purpose: FloePurpose,
        length: usize,
    ) -> Result<Self> {
        type HmacSha384 = Hmac<Sha384>;

        let hmac = match self.params.hash {
            FloeKdf::HkdfExpandSha384 => HmacSha384::new_from_slice(&self.key),
        }?;

        let mut key_array = hmac
            .chain_update(&self.params.get_encoded())
            .chain_update(iv)
            .chain_update(purpose.as_bytes())
            .chain_update(aad)
            .chain_update(&[1])
            .finalize()
            .into_bytes();

        if key_array.len() < length {
            key_array.zeroize();
            Err(Error::UnexpectedInternalError(None))
        } else {
            // HMAC, depending on the HASH we're using and depending on the AEAD we're using, might
            // return more bytes than we need for our key.
            //
            // Use `copy_from_slice()` to avoid a move, which turns into a memcpy under the hood, and
            // only copy the requested number of bytes to the final key vec.
            let mut key = vec![0u8; length];
            key.copy_from_slice(&key_array[..length]);

            // We copied the important bits over, let's zeroize now since we don't want to leave a
            // copy of this, potentially, secret key material around.
            key_array.zeroize();

            // Don't use the `new()` constructor as this would again check the length.
            Ok(Self {
                key,
                params: self.params,
            })
        }
    }
}

impl FloeAead {
    pub(crate) const fn get_id(&self) -> u8 {
        match self {
            FloeAead::AesGcm256 => 0,
        }
    }

    pub(crate) const fn get_key_length(&self) -> usize {
        match self {
            FloeAead::AesGcm256 => 32,
        }
    }

    pub(crate) const fn get_nonce_length(&self) -> usize {
        match self {
            FloeAead::AesGcm256 => 12,
        }
    }

    pub(crate) const fn get_tag_length(&self) -> usize {
        match self {
            FloeAead::AesGcm256 => 16,
        }
    }

    pub(crate) const fn get_rotation_mask(&self) -> u64 {
        match self {
            FloeAead::AesGcm256 => {
                let mut tmp_mask = 1u64 << 20;
                tmp_mask -= 1;
                !tmp_mask
            }
        }
    }

    /// The maximum number of FLOE segments which can be encrypted in a single ciphertext with this algorithm
    pub const fn get_max_segments(&self) -> u64 {
        match self {
            FloeAead::AesGcm256 => 1u64 << 40,
        }
    }
}

impl FloeKdf {
    pub(crate) fn get_id(&self) -> u8 {
        match self {
            FloeKdf::HkdfExpandSha384 => 0,
        }
    }

    pub(crate) fn get_length(&self) -> usize {
        match self {
            FloeKdf::HkdfExpandSha384 => 48,
        }
    }
}

impl FloeParameterSpec {
    pub fn new(aead: FloeAead, hash: FloeKdf, encrypted_segment_length: usize) -> Result<Self> {
        if encrypted_segment_length
            <= aead.get_tag_length() + aead.get_nonce_length() + SEGMENT_LENGTH_PREFIX_LENGTH
        {
            return Err(Error::InvalidInput);
        }
        Ok(FloeParameterSpec {
            aead,
            hash,
            encrypted_segment_length,
            iv_length: DEFAULT_FLOE_IV_LENGTH,
            override_rotation_mask: Option::None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_explicit(
        aead: FloeAead,
        hash: FloeKdf,
        encrypted_segment_length: usize,
        iv_length: usize,
        override_rotation_mask: Option<i64>,
    ) -> FloeParameterSpec {
        let actual_mask = override_rotation_mask.map(|n| u64::from_be_bytes(n.to_be_bytes()));
        Self {
            aead,
            hash,
            encrypted_segment_length,
            iv_length,
            override_rotation_mask: actual_mask,
        }
    }
    pub fn get_aead(&self) -> FloeAead {
        self.aead
    }

    pub fn get_hash(&self) -> FloeKdf {
        self.hash
    }

    /// The length in bytes of an encrypted non-final segment
    pub fn get_encrypted_segment_length(&self) -> usize {
        self.encrypted_segment_length
    }

    /// The length in bytes of the plaintext data in a non-final segment
    pub fn get_plaintext_segment_length(&self) -> usize {
        self.encrypted_segment_length - self.get_segment_overhead()
    }

    pub fn get_segment_overhead(&self) -> usize {
        self.aead.get_tag_length() + self.aead.get_nonce_length() + SEGMENT_LENGTH_PREFIX_LENGTH
    }

    /// The length in bytes of the header, including the encoded parameters, FLOE IV, and Header tag
    pub fn get_header_length(&self) -> usize {
        ENCODED_SPEC_LENGTH + self.iv_length + HEADER_TAG_LENGTH
    }

    /// The length in bytes of the FLOE IV in the header
    pub fn get_iv_length(&self) -> usize {
        self.iv_length
    }

    pub(crate) fn get_encoded(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ENCODED_SPEC_LENGTH);
        encoded.push(self.aead.get_id());
        encoded.push(self.hash.get_id());
        encoded.extend_from_slice(&(self.encrypted_segment_length as u32).to_be_bytes());
        encoded.extend_from_slice(&(self.iv_length as u32).to_be_bytes());
        assert!(encoded.len() == ENCODED_SPEC_LENGTH);
        encoded
    }

    pub(crate) fn get_rotation_mask(&self) -> u64 {
        self.override_rotation_mask
            .or_else(|| Option::Some(self.aead.get_rotation_mask()))
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::{Error, constants::SEGMENT_LENGTH_PREFIX_LENGTH};

    use super::{FloeAead, FloeKdf, FloeParameterSpec, GCM256_IV256_1M, GCM256_IV256_4K};

    #[test]
    pub fn known_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = GCM256_IV256_4K.get_encoded();
        let expected = hex::decode("00000000100000000020")?;
        assert_eq!(encoded, expected);

        let encoded = GCM256_IV256_1M.get_encoded();
        let expected = hex::decode("00000010000000000020")?;
        assert_eq!(encoded, expected);

        assert_ne!(GCM256_IV256_4K.get_encoded(), GCM256_IV256_1M.get_encoded());

        Ok(())
    }

    #[test]
    pub fn create_specs() -> Result<(), Box<dyn std::error::Error>> {
        let spec =
            FloeParameterSpec::new(FloeAead::AesGcm256, FloeKdf::HkdfExpandSha384, 4 * 1024)?;
        assert_eq!(spec, GCM256_IV256_4K);
        assert_eq!(spec.get_encoded(), GCM256_IV256_4K.get_encoded());
        assert_ne!(spec, GCM256_IV256_1M);

        let spec =
            FloeParameterSpec::new(FloeAead::AesGcm256, FloeKdf::HkdfExpandSha384, 1024 * 1024)?;
        assert_ne!(spec, GCM256_IV256_4K);
        assert_eq!(spec.get_encoded(), GCM256_IV256_1M.get_encoded());
        assert_eq!(spec, GCM256_IV256_1M);

        let overhead = FloeAead::AesGcm256.get_nonce_length()
            + FloeAead::AesGcm256.get_tag_length()
            + SEGMENT_LENGTH_PREFIX_LENGTH;
        // Minimum size is encrypting one byte
        FloeParameterSpec::new(FloeAead::AesGcm256, FloeKdf::HkdfExpandSha384, overhead + 1)?;

        let failed_result =
            FloeParameterSpec::new(FloeAead::AesGcm256, FloeKdf::HkdfExpandSha384, overhead);
        assert!(failed_result.is_err());
        let actual_error = failed_result.err().unwrap();
        if let Error::InvalidInput = actual_error {
            // expected
        } else {
            panic!("Wrong error. {:?}", actual_error);
        }

        let failed_result =
            FloeParameterSpec::new(FloeAead::AesGcm256, FloeKdf::HkdfExpandSha384, overhead - 1);
        assert!(failed_result.is_err());
        let actual_error = failed_result.err().unwrap();
        if let Error::InvalidInput = actual_error {
            // expected
        } else {
            panic!("Wrong error. {:?}", actual_error);
        }

        Ok(())
    }
}
