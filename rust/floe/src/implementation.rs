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
    Error, FloeKey, FloeSequentialCryptor, Result,
    constants::{INTERNAL_SEGMENT_PREFIX, SEGMENT_LENGTH_PREFIX_LENGTH},
    ra,
};

/// Exposes the FLOE streaming (online) encryption APIs.
/// See [FloeSequentialCryptor] for sample usage.
pub struct FloeSequentialEncryptor {
    ra_core: ra::FloeEncryptor,
    counter: u64,
    closed: bool,
}

impl FloeSequentialEncryptor {
    pub fn new(key: &FloeKey, aad: &[u8]) -> Result<Self> {
        let ra_core = ra::FloeEncryptor::new(key, aad)?;

        Ok(Self {
            ra_core,
            counter: 0,
            closed: false,
        })
    }

    pub fn get_header(&self) -> &[u8] {
        self.ra_core.get_header()
    }
}

impl FloeSequentialCryptor for FloeSequentialEncryptor {
    fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.ra_core.get_parameter_spec()
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
            return Err(Error::InvalidInput);
        }
        if self.counter >= self.get_parameter_spec().get_aead().get_max_segments() - 1 {
            return Err(Error::SegmentOverflow);
        }
        if output.len() < self.get_output_size() {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: self.get_output_size(),
            });
        }
        self.ra_core
            .encrypt_segment(input, output, self.counter, false)?;

        self.counter += 1;

        Ok(())
    }

    fn process_last_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if input.len() > self.get_input_size() {
            return Err(Error::InvalidInput);
        }
        let output_size = self.size_of_last_output(input.len())?;
        if output.len() < output_size {
            return Err(Error::DataOverflow {
                actual: output.len(),
                expected: output_size,
            });
        }
        if self.counter >= self.get_parameter_spec().get_aead().get_max_segments() {
            return Err(Error::SegmentOverflow);
        }
        self.ra_core
            .encrypt_segment(input, output, self.counter, true)?;

        self.closed = true;

        Ok(())
    }

    fn size_of_last_output(&self, input_size: usize) -> Result<usize> {
        if input_size > self.get_input_size() {
            return Err(Error::InvalidInput);
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
        self.closed
    }
}

/// Exposes the FLOE streaming (online) decryption APIs.
/// See [FloeSequentialCryptor] for sample usage.
pub struct FloeSequentialDecryptor {
    ra_core: ra::FloeDecryptor,
    counter: u64,
    closed: bool,
}

impl FloeSequentialDecryptor {
    pub fn new(key: &FloeKey, aad: &[u8], header: &[u8]) -> Result<Self> {
        let ra_core = ra::FloeDecryptor::new(key, aad, header)?;
        Ok(Self {
            ra_core,
            counter: 0,
            closed: false,
        })
    }
}

impl FloeSequentialCryptor for FloeSequentialDecryptor {
    fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.ra_core.get_parameter_spec()
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
            return Err(Error::InvalidInput);
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
            return Err(Error::MalformedSegment);
        }
        if self.counter >= self.get_parameter_spec().get_aead().get_max_segments() {
            return Err(Error::SegmentOverflow);
        }
        self.ra_core
            .decrypt_segment(input, output, self.counter, false)?;
        self.counter += 1;
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
            return Err(Error::MalformedSegment);
        }

        self.ra_core
            .decrypt_segment(input, output, self.counter, true)?;
        self.closed = true;
        Ok(())
    }

    fn size_of_last_output(&self, input_size: usize) -> Result<usize> {
        let aead = self.get_parameter_spec().get_aead();
        let min_size =
            SEGMENT_LENGTH_PREFIX_LENGTH + aead.get_nonce_length() + aead.get_tag_length();
        if input_size < min_size || input_size > self.get_input_size() {
            return Err(Error::InvalidInput);
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
        self.closed
    }
}
