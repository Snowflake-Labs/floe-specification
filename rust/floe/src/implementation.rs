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

use crate::{
    Error, FloeAead, FloeCryptor, FloeKey, Result,
    constants::{HEADER_TAG_LENGTH, INTERNAL_SEGMENT_PREFIX, SEGMENT_LENGTH_PREFIX_LENGTH},
    types::FloePurpose,
};
use aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use aes_gcm::Aes256Gcm;
use subtle::ConstantTimeEq;

// This exists solely to make handling different implementations of Aead possible
#[allow(clippy::large_enum_variant)] // Types can't be boxed
pub enum AeadHolder {
    Unset,
    AesGcm256(aes_gcm::Aes256Gcm),
}

struct CryptoCore {
    message_key: FloeKey,
    floe_iv: Vec<u8>,
    aad: Vec<u8>,
    counter: u64,
    last_masked_counter: u64,
    closed: bool,

    aead: AeadHolder,
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
            counter: 0,
            closed: false,
            aead: AeadHolder::Unset,
            last_masked_counter: u64::MAX,
        })
    }

    fn use_current_key(&mut self) -> Result<()> {
        let mask = self.message_key.get_parameters().get_rotation_mask();
        let masked_counter = self.counter & mask;
        if masked_counter != self.last_masked_counter {
            let session_key = self.message_key.derive_key(
                &self.floe_iv,
                &self.aad,
                crate::types::FloePurpose::SegmentKey(masked_counter),
                self.message_key
                    .get_parameters()
                    .get_aead()
                    .get_key_length(),
            )?;
            self.aead = match self.message_key.get_parameters().get_aead() {
                FloeAead::AesGcm256 => {
                    AeadHolder::AesGcm256(Aes256Gcm::new_from_slice(&session_key.key)?)
                }
            };
            self.last_masked_counter = masked_counter
        }
        Ok(())
    }

    fn build_segment_aad(&self, last: bool) -> [u8; 9] {
        let mut result = [0u8; 9];
        result[0..8].copy_from_slice(&self.counter.to_be_bytes());
        result[8] = if last { 1 } else { 0 };
        result
    }

    fn encrypt(&self, msg: &[u8], aad: &[u8], output: &mut [u8]) -> Result<()> {
        let floe_aead = self.message_key.get_parameters().get_aead();
        let iv_length = floe_aead.get_nonce_length();
        if output.len() < iv_length + floe_aead.get_tag_length() + msg.len() {
            return Err(Error::UnexpectedInternalError(None));
        }
        OsRng.fill_bytes(&mut output[..iv_length]);
        let nonce = &output[..iv_length];

        let payload = Payload { msg, aad };
        let ct = match &self.aead {
            AeadHolder::Unset => return Err(Error::UnexpectedInternalError(None)),
            AeadHolder::AesGcm256(cipher) => cipher.encrypt(nonce.into(), payload)?,
        };
        output[iv_length..iv_length + ct.len()].copy_from_slice(&ct);
        Ok(())
    }

    fn decrypt(&self, msg: &[u8], aad: &[u8], output: &mut [u8]) -> Result<()> {
        let floe_aead = self.message_key.get_parameters().get_aead();
        let iv_length = floe_aead.get_nonce_length();
        if msg.len() < iv_length + floe_aead.get_tag_length() {
            return Err(Error::UnexpectedInternalError(None));
        }
        if output.len() < msg.len() - iv_length - floe_aead.get_tag_length() {
            return Err(Error::UnexpectedInternalError(None));
        }
        let nonce = &msg[..iv_length];

        let payload = Payload {
            msg: &msg[iv_length..],
            aad,
        };
        let pt = match &self.aead {
            AeadHolder::Unset => return Err(Error::UnexpectedInternalError(None)),
            AeadHolder::AesGcm256(cipher) => cipher
                .decrypt(nonce.into(), payload)
                .map_err(|_| Error::BadTag)?,
        };
        output[..pt.len()].copy_from_slice(&pt);
        Ok(())
    }
}

pub struct FloeEncryptor {
    header: Vec<u8>,
    core: CryptoCore,
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
}

impl FloeCryptor for FloeEncryptor {
    fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    fn get_input_size(&self) -> usize {
        self.get_parameter_spec().get_plaintext_segment_length()
    }

    fn get_output_size(&self) -> usize {
        self.get_parameter_spec().get_encrypted_segment_length()
    }

    fn process_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if input.len() != self.get_input_size() {
            return Error::invalid_input(&format!(
                "Expected input of size {} but was {}",
                self.get_input_size(),
                input.len()
            ));
        }
        if self.core.counter >= self.get_parameter_spec().get_aead().get_max_segments() {
            return Err(Error::SegmentOverflow);
        }
        if output.len() < self.get_output_size() {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: self.get_output_size(),
            });
        }
        self.core.use_current_key()?;

        output[0..SEGMENT_LENGTH_PREFIX_LENGTH].copy_from_slice(&INTERNAL_SEGMENT_PREFIX.to_be_bytes());

        let aad = self.core.build_segment_aad(false);
        self.core
            .encrypt(input, &aad, &mut output[SEGMENT_LENGTH_PREFIX_LENGTH..])?;
        self.core.counter += 1;

        Ok(())
    }

    fn process_last_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if input.len() > self.get_input_size() {
            return Error::invalid_input(&format!(
                "Expected input of size no more than {} but was {}",
                self.get_input_size(),
                input.len()
            ));
        }
        let output_size = self.size_of_last_output(input.len())?;
        if output.len() < output_size {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: output_size,
            });
        }
        self.core.use_current_key()?;

        output[0..SEGMENT_LENGTH_PREFIX_LENGTH]
            .copy_from_slice(&(output_size as u32).to_be_bytes());
        let aad = self.core.build_segment_aad(true);
        self.core
            .encrypt(input, &aad, &mut output[SEGMENT_LENGTH_PREFIX_LENGTH..])?;
        self.core.closed = true;

        Ok(())
    }

    fn size_of_last_output(&self, input_size: usize) -> Result<usize> {
        if input_size > self.get_input_size() {
            return Err(Error::InvalidInput(format!(
                "Last segment must be between 0 and {}. Was {}",
                self.get_input_size(),
                input_size
            )));
        }
        let aead = self.get_parameter_spec().get_aead();
        Ok(SEGMENT_LENGTH_PREFIX_LENGTH
            + aead.get_nonce_length()
            + input_size
            + aead.get_tag_length())
    }

    fn finish(&self) -> Result<()> {
        if self.is_closed() {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn is_closed(&self) -> bool {
        self.core.closed
    }
}

pub struct FloeDecryptor {
    core: CryptoCore,
}

impl FloeDecryptor {
    pub fn new(key: &FloeKey, aad: &[u8], header: &[u8]) -> Result<Self> {
        let params = &key.get_parameters();
        if header.len() < params.get_header_length() {
            return Err(Error::BadHeader(format!(
                "Header too short. Expected {} but was {}",
                params.get_header_length(),
                header.len()
            )));
        }
        let header = &header[..params.get_header_length()];
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
}

impl FloeCryptor for FloeDecryptor {
    fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    fn get_input_size(&self) -> usize {
        self.get_parameter_spec().get_encrypted_segment_length()
    }

    fn get_output_size(&self) -> usize {
        self.get_parameter_spec().get_plaintext_segment_length()
    }

    fn process_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if input.len() != self.get_input_size() {
            return Error::invalid_input(&format!(
                "Expected input of size {} but was {}",
                self.get_input_size(),
                input.len()
            ));
        }
        if output.len() < self.get_output_size() {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: self.get_output_size(),
            });
        }
        let segment_length_header =
            u32::from_be_bytes(input[..SEGMENT_LENGTH_PREFIX_LENGTH].try_into()?);
        if (segment_length_header as usize) == input.len() {
            // We've hit the last segment and our caller hasn't noticed.
            return self.process_last_segment(input, output);
        } else if segment_length_header != INTERNAL_SEGMENT_PREFIX {
            return Err(Error::MalformedSegment(format!(
                "Expected segment prefix of FFFFFF but was {:?}",
                &input[0..SEGMENT_LENGTH_PREFIX_LENGTH]
            )));
        }
        if self.core.counter >= self.get_parameter_spec().get_aead().get_max_segments() {
            return Err(Error::SegmentOverflow);
        }
        self.core.use_current_key()?;
        self.core.decrypt(
            &input[SEGMENT_LENGTH_PREFIX_LENGTH..],
            &self.core.build_segment_aad(false),
            output,
        )?;
        self.core.counter += 1;
        Ok(())
    }

    fn process_last_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        // Contains length checks
        let output_size = self.size_of_last_output(input.len())?;

        if output.len() < output_size {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: self.get_output_size(),
            });
        }
        let input_size = u32::from_be_bytes(input[..SEGMENT_LENGTH_PREFIX_LENGTH].try_into()?);
        if (input_size as usize) != input.len() {
            return Err(Error::MalformedSegment(format!(
                "Expected segment of length {} but was {}",
                input_size,
                input.len()
            )));
        }

        self.core.use_current_key()?;
        self.core.decrypt(
            &input[SEGMENT_LENGTH_PREFIX_LENGTH..],
            &self.core.build_segment_aad(true),
            output,
        )?;
        self.core.closed = true;
        Ok(())
    }

    fn size_of_last_output(&self, input_size: usize) -> Result<usize> {
        let aead = self.get_parameter_spec().get_aead();
        let min_size =
            SEGMENT_LENGTH_PREFIX_LENGTH + aead.get_nonce_length() + aead.get_tag_length();
        if input_size < min_size || input_size > self.get_input_size() {
            return Err(Error::InvalidInput(format!(
                "Last segment must be between {} and {}. Was {}",
                min_size,
                self.get_input_size(),
                input_size
            )));
        }
        Ok(input_size - min_size)
    }

    fn finish(&self) -> Result<()> {
        if self.is_closed() {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn is_closed(&self) -> bool {
        self.core.closed
    }
}
