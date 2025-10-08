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

use crate::{FloeParameterSpec, Result};

/**
 * Trait representing a generic FLOE transformation, encryption or decryption.
 * Specific implementations may be *more* flexible in what they accept.
 */
pub trait FloeCryptor {
    fn get_parameter_spec(&self) -> FloeParameterSpec;
    /**
     * The length of `input` to [FloeCryptor::process_segment]
     * and maximum length of `input` to [FloeCryptor::process_last_segment].
     */
    fn get_input_size(&self) -> usize;
    /**
     * The amount of data written in `output` by [FloeCryptor::process_segment]
     * and maximum amount written by [FloeCryptor::process_last_segment].
     */
    fn get_output_size(&self) -> usize;
    /**
     * Transform (encrypt or decrypt) [FloeCryptor::get_input_size] bytes of `input`
     * and write the resulting [FloeCryptor::get_output_size] bytes of output to `output`.
     */
    fn process_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()>;
    /**
     * Transform (encrypt or decrypt) at most [FloeCryptor::get_input_size] bytes of `input`
     * and write the resulting [FloeCryptor::size_of_last_output] bytes of output to `output`.
     */
    fn process_last_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()>;
    /// The length of data written by [FloeCryptor::process_last_segment] when provided an input of `input_size` length.
    fn size_of_last_output(&self, input_size: usize) -> Result<usize>;
    /// Returns a result indicating if this transformation has completed successfully.
    fn finish(&self) -> Result<()>;
    fn is_closed(&self) -> bool;
}
