// Copyright 2026 Snowflake Inc.
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
// This exists solely to make handling different implementations of Aead possible

use crate::{
    Error, FloeAead, FloeKey, Result,
    constants::{HEADER_TAG_LENGTH, INTERNAL_SEGMENT_PREFIX, SEGMENT_LENGTH_PREFIX_LENGTH},
    types::FloePurpose,
};

use aead::{AeadInPlace, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::Aes256Gcm;
use subtle::ConstantTimeEq;

struct CryptoCore {
    message_key: FloeKey,
    floe_iv: Vec<u8>,
    aad: Vec<u8>,
}

impl CryptoCore {
    fn new(message_key: FloeKey, floe_iv: Vec<u8>, aad: Vec<u8>) -> Result<CryptoCore> {
        if message_key.key.len() != message_key.get_parameters().get_hash().get_length() {
            return Err(Error::InvalidInput(format!(
                "Invalid key size. Was {}",
                message_key.key.len()
            )));
        }
        if floe_iv.len() < 32 {
            return Err(Error::InvalidInput(format!(
                "Invalid FLOE IV size. Was {}",
                floe_iv.len()
            )));
        }
        Ok(Self {
            message_key,
            floe_iv,
            aad,
        })
    }

    fn get_epoch_key(&self, counter: u64) -> Result<FloeKey> {
        let mask = self.message_key.get_parameters().get_rotation_mask();
        let masked_counter = counter & mask;
        self.message_key.derive_key(
            &self.floe_iv,
            &self.aad,
            crate::types::FloePurpose::SegmentKey(masked_counter),
            self.message_key
                .get_parameters()
                .get_aead()
                .get_key_length(),
        )
    }

    fn build_segment_aad(&self, counter: u64, last: bool) -> [u8; 9] {
        let mut result = [0u8; 9];
        result[0..8].copy_from_slice(&counter.to_be_bytes());
        result[8] = if last { 1 } else { 0 };
        result
    }

    fn encrypt(
        &self,
        epoch_key: &FloeKey,
        msg: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        let floe_aead = epoch_key.get_parameters().get_aead();
        let iv_length = floe_aead.get_nonce_length();
        if output.len() < iv_length + floe_aead.get_tag_length() + msg.len() {
            return Err(Error::UnexpectedInternalError(None));
        }
        OsRng.fill_bytes(&mut output[..iv_length]);
        // let nonce = &output[..iv_length];

        match floe_aead {
            FloeAead::AesGcm256 => {
                let gcm = Aes256Gcm::new_from_slice(&epoch_key.key)?;
                output[iv_length..iv_length + msg.len()].copy_from_slice(msg);
                let tag = {
                    let [nonce, body] = output
                        .get_disjoint_mut([0..iv_length, iv_length..iv_length + msg.len()])?;
                    gcm.encrypt_in_place_detached(nonce[..iv_length].into(), aad, body)
                }?;
                output[iv_length + msg.len()..].copy_from_slice(tag.as_slice());
            }
        };
        Ok(())
    }

    fn decrypt(
        &self,
        epoch_key: &FloeKey,
        msg: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        let floe_aead = epoch_key.get_parameters().get_aead();
        let iv_length = floe_aead.get_nonce_length();
        let tag_length = floe_aead.get_tag_length();
        if msg.len() < iv_length + floe_aead.get_tag_length() {
            return Err(Error::UnexpectedInternalError(None));
        }
        if output.len() < msg.len() - iv_length - tag_length {
            return Err(Error::UnexpectedInternalError(None));
        }
        let nonce = &msg[..iv_length];
        let tag = &msg[msg.len() - tag_length..];
        output.copy_from_slice(&msg[iv_length..msg.len() - tag_length]);

        match floe_aead {
            FloeAead::AesGcm256 => {
                let gcm = Aes256Gcm::new_from_slice(&epoch_key.key)?;
                gcm.decrypt_in_place_detached(nonce.into(), aad, output, tag.into())?;
            }
        };
        Ok(())
    }
}

pub struct FloeEncryptor {
    core: CryptoCore,
    header: Vec<u8>,
}

impl FloeEncryptor {
    pub fn new(key: &FloeKey, aad: &[u8]) -> Result<Self> {
        let params = &key.get_parameters();
        let mut floe_iv = vec![0u8; params.get_iv_length()];
        let mut rng = OsRng;
        rng.fill_bytes(&mut floe_iv);

        let mut header = params.get_encoded();
        header.extend(&floe_iv);
        let header_tag = &key
            .derive_key(&floe_iv, aad, FloePurpose::HeaderTag, HEADER_TAG_LENGTH)?
            .key;
        header.extend(header_tag);
        let message_key = key.derive_key(
            &floe_iv,
            aad,
            FloePurpose::MessageKey,
            params.get_hash().get_length(),
        )?;
        let core = CryptoCore::new(message_key, floe_iv, aad.to_owned())?;

        Ok(Self { header, core })
    }

    pub fn get_header(&self) -> &[u8] {
        &self.header
    }

    pub fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    pub fn encrypt_segment(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<()> {
        if is_final {
            if plaintext.len() > self.get_parameter_spec().get_plaintext_segment_length() {
                return Error::invalid_input("");
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() {
                return Err(Error::SegmentOverflow);
            }
            let output_size: u32 =
                (plaintext.len() + self.get_parameter_spec().get_segment_overhead()).try_into()?;
            ciphertext[0..SEGMENT_LENGTH_PREFIX_LENGTH].copy_from_slice(&output_size.to_be_bytes());
        } else {
            if plaintext.len() != self.get_parameter_spec().get_plaintext_segment_length() {
                return Error::invalid_input("");
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() - 1 {
                return Err(Error::SegmentOverflow);
            }
            ciphertext[0..SEGMENT_LENGTH_PREFIX_LENGTH]
                .copy_from_slice(&INTERNAL_SEGMENT_PREFIX.to_be_bytes());
        }
        if ciphertext.len() != plaintext.len() + self.get_parameter_spec().get_segment_overhead() {
            return Err(Error::InvalidInput(
                "Output slice is the incorrect length".to_string(),
            ));
        }
        let aead_key = self.core.get_epoch_key(segment_number)?;
        let aad = self.core.build_segment_aad(segment_number, is_final);
        self.core.encrypt(
            &aead_key,
            plaintext,
            &aad,
            &mut ciphertext[SEGMENT_LENGTH_PREFIX_LENGTH..],
        )?;

        Ok(())
    }
}

pub struct FloeDecryptor {
    core: CryptoCore,
}

impl FloeDecryptor {
    pub fn new(key: &FloeKey, aad: &[u8], header: &[u8]) -> Result<Self> {
        let params = &key.get_parameters();
        if header.len() != params.get_header_length() {
            return Err(Error::BadHeader(format!(
                "Header wrong length. Expected {} but was {}",
                params.get_header_length(),
                header.len()
            )));
        }
        let expected_encoded = params.get_encoded();
        // This does not need to be constant time
        if expected_encoded != header[0..expected_encoded.len()] {
            return Err(Error::BadHeader("Invalid parameters".to_string()));
        }
        let floe_iv =
            &header[expected_encoded.len()..expected_encoded.len() + params.get_iv_length()];
        let tag = &header[expected_encoded.len() + params.get_iv_length()..];

        let header_tag = &key
            .derive_key(floe_iv, aad, FloePurpose::HeaderTag, HEADER_TAG_LENGTH)?
            .key;

        // This next comparison *must* be constant time
        let tag_valid: bool = header_tag.ct_eq(tag).into();
        if !tag_valid {
            return Err(Error::BadHeaderTag);
        }

        let message_key = key.derive_key(
            floe_iv,
            aad,
            FloePurpose::MessageKey,
            params.get_hash().get_length(),
        )?;
        let core = CryptoCore::new(message_key, floe_iv.to_owned(), aad.to_owned())?;

        Ok(Self { core })
    }

    pub fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    /*
       decryptSegment(State, EncryptedSegment, position, is_final) -> (State, Plaintext)
           if is_final:
               assert(len(EncryptedSegment) >= AEAD_IV_LEN + AEAD_TAG_LEN + 4)
               assert(len(EncryptedSegment) <= ENC_SEG_LEN)
               assert(BE2I(EncryptedSegment[:4]) == len(EncryptedSegment))
               aad_tail = 0x01
           else:
               assert(len(EncryptedSegment) == ENC_SEG_LEN)
               assert(BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF)
               aad_tail = 0x00

           aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, position)
           (aead_iv, aead_ciphertext, tag) = SPLIT(EncryptedSegment[4:], AEAD_IV_LEN, AEAD_TAG_LEN)
           aead_aad = I2BE(position, 8) || aad_tail

           // Next line will throw if AEAD decryption fails
           Plaintext = AEAD_DEC(aead_key, aead_iv, aead_ciphertext, aead_aad, tag)

           return (State, Plaintext)
    */
    pub fn decrypt_segment(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<()> {
        if is_final {
            if ciphertext.len() < self.get_parameter_spec().get_segment_overhead() {
                return Err(Error::Truncated);
            }
            if ciphertext.len() > self.get_parameter_spec().get_encrypted_segment_length() {
                return Err(Error::MalformedSegment("Segment is too long".to_string()));
            }
            let parsed_len = u32::from_be_bytes(
                ciphertext[..SEGMENT_LENGTH_PREFIX_LENGTH]
                    .try_into()
                    .unwrap(),
            ) as usize;
            if parsed_len != ciphertext.len() {
                return Err(Error::MalformedSegment(
                    "Segment header length wrong".to_string(),
                ));
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() {
                return Err(Error::SegmentOverflow);
            }
        } else {
            if ciphertext.len() != self.get_parameter_spec().get_encrypted_segment_length() {
                return Err(Error::MalformedSegment(
                    "Segment is too wrong length".to_string(),
                ));
            }
            let parsed_len = u32::from_be_bytes(
                ciphertext[..SEGMENT_LENGTH_PREFIX_LENGTH]
                    .try_into()
                    .unwrap(),
            );
            if parsed_len != INTERNAL_SEGMENT_PREFIX {
                return Err(Error::MalformedSegment(
                    "Segment header length wrong".to_string(),
                ));
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() - 1 {
                return Err(Error::SegmentOverflow);
            }
        }
        if ciphertext.len() != plaintext.len() + self.get_parameter_spec().get_segment_overhead() {
            return Err(Error::InvalidInput(
                "Output slice is the incorrect length".to_string(),
            ));
        }
        let aead_key = self.core.get_epoch_key(segment_number)?;
        let aad = self.core.build_segment_aad(segment_number, is_final);
        self.core.decrypt(
            &aead_key,
            &ciphertext[SEGMENT_LENGTH_PREFIX_LENGTH..],
            &aad,
            plaintext,
        )?;
        Ok(())
    }
}
