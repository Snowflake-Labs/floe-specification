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
 * Trait representing a generic FLOE sequential transformation, encryption or decryption.
 * Specific implementations may be *more* flexible in what they accept.
 * ```rust
 * use floe::{Error, FloeKey, FloeSequentialCryptor, FloeSequentialDecryptor, FloeSequentialEncryptor, GCM256_IV256_1M, Result};
 *
 * // Normally you'd save your key in some safe location. But for the demo we'll generate a random one
 * // GCM256_IV256_1M is a generally useful chunk size
 * let sample_key = FloeKey::new_random(GCM256_IV256_1M);
 * assert!(sample_key.is_ok());
 * let sample_key = sample_key.unwrap();
 * // We'll just use an all one plaintext for the demo and large enough to be multiple segments
 * let plaintext = vec![1u8; 3 * 1024 * 1024 + 512];
 * let aad = b"This is some aad";
 *
 * let ciphertext = encrypt_data(&sample_key, &plaintext, aad);
 * assert!(ciphertext.is_ok());
 * let ciphertext = ciphertext.unwrap();
 *
 * // Finally, decrypt the result
 * let decrypted = decrypt_data(&sample_key, &ciphertext, aad);
 * //assert!(decrypted.is_ok());
 * let decrypted = decrypted.unwrap();
 * assert_eq!(decrypted, plaintext);
 *
 * fn encrypt_data(key: &FloeKey, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
 *   let mut encryptor = FloeSequentialEncryptor::new(key, aad)?;
 *   let mut result = encryptor.get_header().to_vec();
 *   let mut buff = vec![0u8; encryptor.get_output_size()];
 *   for chunk in data.chunks(encryptor.get_input_size()) {
 *     if chunk.len() != encryptor.get_input_size() {
 *       // Last chunk
 *       let last_len = encryptor.size_of_last_output(chunk.len())?;
 *       encryptor.process_last_segment(chunk, &mut buff[..last_len])?;
 *       result.extend(&buff[..last_len]);
 *     } else {
 *       encryptor.process_segment(chunk, &mut buff)?;
 *       result.extend(&buff);
 *     }
 *   }
 *   // Make sure that we've emitted a final segment
 *   if !encryptor.is_closed() {
 *     let last_len = encryptor.size_of_last_output(0)?;
 *     encryptor.process_last_segment(&[], &mut buff[..last_len])?;
 *     result.extend(&buff[..last_len]);
 *   }
 *   Ok(result)
 * }
 *
 *  fn decrypt_data(key: &FloeKey, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
 *   let header_length = key.get_parameters().get_header_length();
 *   let header = &data[..header_length];
 *   let ciphertext = &data[header_length..];
 *   let mut decryptor = FloeSequentialDecryptor::new(key, aad, header)?;
 *   let mut result = vec![];
 *   let mut buff = vec![0u8; decryptor.get_output_size()];
 *   for chunk in ciphertext.chunks(decryptor.get_input_size()) {
 *     if chunk.len() != decryptor.get_input_size() {
 *       // Last chunk
 *       let last_len = decryptor.size_of_last_output(chunk.len())?;
 *       decryptor.process_last_segment(chunk, &mut buff[..last_len])?;
 *       result.extend(&buff[..last_len]);
 *     } else {
 *       decryptor.process_segment(chunk, &mut buff)?;
 *       result.extend(&buff);
 *     }
 *   }
 *   if !decryptor.is_closed() {
 *     return Err(Error::Truncated);
 *   }
 *   Ok(result)
 * }
 * ```
 */
pub trait FloeSequentialCryptor {
    fn get_parameter_spec(&self) -> FloeParameterSpec;
    /**
     * The length of `input` to [FloeSequentialCryptor::process_segment]
     * and maximum length of `input` to [FloeSequentialCryptor::process_last_segment].
     */
    fn get_input_size(&self) -> usize;
    /**
     * The amount of data written in `output` by [FloeSequentialCryptor::process_segment]
     * and maximum amount written by [FloeSequentialCryptor::process_last_segment].
     */
    fn get_output_size(&self) -> usize;
    /**
     * Transform (encrypt or decrypt) [FloeSequentialCryptor::get_input_size] bytes of `input`
     * and write the resulting [FloeSequentialCryptor::get_output_size] bytes of output to `output`.
     */
    fn process_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()>;
    /**
     * Transform (encrypt or decrypt) at most [FloeSequentialCryptor::get_input_size] bytes of `input`
     * and write the resulting [FloeSequentialCryptor::size_of_last_output] bytes of output to `output`.
     */
    fn process_last_segment(&mut self, input: &[u8], output: &mut [u8]) -> Result<()>;
    /// The length of data written by [FloeSequentialCryptor::process_last_segment] when provided an input of `input_size` length.
    fn size_of_last_output(&self, input_size: usize) -> Result<usize>;
    /// Returns a result indicating if this transformation has completed successfully.
    fn finish(&self) -> Result<()>;
    fn is_closed(&self) -> bool;
}
