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

use aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use rand::{TryRng, rngs::SysRng};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct CryptoCore {
    message_key: FloeKey,
    floe_iv: Vec<u8>,
    aad: Vec<u8>,
}

impl CryptoCore {
    /// Instantiates the core cryptographic logic of FLOE given the *message_key*.
    /// (The message key is derived from the main FLOE key passed in by the user.)
    /// This method returns an error if the parameters are not compatible with the
    /// [FloeParameterSpec] associated with the message_key (currently due to length).
    fn new(message_key: FloeKey, floe_iv: Vec<u8>, aad: Vec<u8>) -> Result<CryptoCore> {
        if message_key.key.len() != message_key.get_parameters().get_hash().get_length() {
            return Err(Error::InvalidInput);
        }
        if floe_iv.len() < 32 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            message_key,
            floe_iv,
            aad,
        })
    }

    /// Derives the Epoch Key to be used directly with the AEAD to encrypt/decrypt the segment with a segment index of `counter`.
    fn get_epoch_key(&self, counter: u64) -> FloeKey {
        let mask = self.message_key.get_parameters().get_rotation_mask();
        let masked_counter = counter & mask;
        self.message_key.derive_key(
            &self.floe_iv,
            &self.aad,
            crate::types::FloePurpose::from_segment(masked_counter),
            self.message_key
                .get_parameters()
                .get_aead()
                .get_key_length(),
        )
    }

    /// Creates the AAD to be passed to the AEAD when encrypting/decrypting the specified segment.
    fn build_segment_aad(&self, counter: u64, last: bool) -> [u8; 9] {
        let mut result = [0u8; 9];
        result[0..8].copy_from_slice(&counter.to_be_bytes());
        result[8] = if last { 1 } else { 0 };
        result
    }

    /// Encrypt the specified segment.
    /// `epoch_key` comes from [CryptoCore::get_epoch_key].
    /// `aad` comes from [CryptoCore::build_segment_aad].
    fn encrypt(&self, epoch_key: &FloeKey, msg: &[u8], aad: &[u8], output: &mut [u8]) {
        let floe_aead = epoch_key.get_parameters().get_aead();
        let iv_length = floe_aead.get_nonce_length();
        debug_assert_eq!(
            output.len(),
            iv_length + floe_aead.get_tag_length() + msg.len()
        );
        SysRng
            .try_fill_bytes(&mut output[..iv_length])
            .expect("The system RNG should never fail");

        match floe_aead {
            FloeAead::AesGcm256 => {
                let gcm = Aes256Gcm::new_from_slice(&epoch_key.key).expect(
                    "Unexpected because we explicitly construct keys of the proper length.",
                );
                output[iv_length..iv_length + msg.len()].copy_from_slice(msg);
                let (nonce, rest) = output.split_at_mut(iv_length);
                let (body, rest) = rest.split_at_mut(msg.len());
                let (tag_dest, rest) = rest.split_at_mut(floe_aead.get_tag_length());
                debug_assert!(rest.is_empty());

                let tag = gcm
                    .encrypt_in_place_detached(nonce[..iv_length].into(), aad, body)
                    .expect("Encryption is never expected to fail.");
                tag_dest.copy_from_slice(tag.as_slice());
            }
        };
    }

    /// Decrypt the specified segment. Returns an error if the AEAD tag is incorrect.
    /// `epoch_key` comes from [CryptoCore::get_epoch_key].
    /// `aad` comes from [CryptoCore::build_segment_aad].
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
        debug_assert!(msg.len() >= iv_length + floe_aead.get_tag_length());
        debug_assert_eq!(output.len(), msg.len() - iv_length - tag_length);
        let (nonce, rest) = msg.split_at(iv_length);
        let (body, tag) = rest.split_at(rest.len() - tag_length);
        output.copy_from_slice(body);

        match floe_aead {
            FloeAead::AesGcm256 => {
                let gcm = Aes256Gcm::new_from_slice(&epoch_key.key)?;
                gcm.decrypt_in_place_detached(nonce.into(), aad, output, tag.into())?;
            }
        };
        Ok(())
    }
}

/**
 * Exposes the FLOE random-access encryption APIs.
 *
 * <div class="warning">The random-access APIs do not directly protect you against truncation attacks
 * or prevent you from incorrectly encrypting the same segment multiple times.</div>
 */
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FloeEncryptor {
    core: CryptoCore,
    header: Vec<u8>,
}

impl FloeEncryptor {
    /**
    Creates a new instance of [FloeEncryptor].

    Corresponds to `startEncryption` from the specification.
    */
    /*
     ```plain
       startEncryption(key, aad) -> (State, Header)
           iv = RND(FLOE_IV_LEN)

           HeaderPrefix = PARAM_ENCODE(params) || iv
           HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
           MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
           Header = HeaderPrefix || HeaderTag

           State = {MessageKey, iv, aad}
           return (State, Header)
       ```
    */
    pub fn new(key: &FloeKey, aad: &[u8]) -> Result<Self> {
        let params = &key.get_parameters();
        // iv = RND(FLOE_IV_LEN)
        let mut floe_iv = vec![0u8; params.get_iv_length()];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut floe_iv)?;

        // HeaderPrefix = PARAM_ENCODE(params) || iv
        let mut header = params.get_encoded();
        header.extend(&floe_iv);
        // HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
        let header_tag = &key
            .derive_key(&floe_iv, aad, FloePurpose::HeaderTag, HEADER_TAG_LENGTH)
            .key;
        // Header = HeaderPrefix || HeaderTag
        header.extend(header_tag);
        // MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
        let message_key = key.derive_key(
            &floe_iv,
            aad,
            FloePurpose::MessageKey,
            params.get_hash().get_length(),
        );

        // State = {MessageKey, iv, aad}
        let core = CryptoCore::new(message_key, floe_iv, aad.to_owned())?;

        // return (State, Header)
        Ok(Self { header, core })
    }

    pub fn get_header(&self) -> &[u8] {
        &self.header
    }

    pub fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    /**
    Encrypts a single FLOE segment with an index of `segment_number`.

    `is_final` must be true only for the segment corresponding to the end of the entire ciphertext.
    That is to say that if `encrypt_segment` is called in a monotonically increasing order of `segment_number`
    values then `is_final` is true only for the last of those calls.
    `ciphertext` is an output parameter which must be exactly [FloeEncryptor::get_size_of_output]`(plaintext.len())` long.
    This method corresponds to `encryptSegment` from the specification.
    */
    /*
    ```plain
    encryptSegment(State, plaintext, segment_number, is_final) -> (State, EncryptedSegment)
       assert(len(plaintext) >= 0)
       if is_final:
           assert(len(plaintext) <= ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
           aad_tail = 0x01
       else:
           assert(len(plaintext) == ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
           aad_tail = 0x00

       aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, segment_number)
       aead_iv = RND(AEAD_IV_LEN)
       aead_aad = I2BE(segment_number, 8) || aad_tail
       (aead_ciphertext, tag) = AEAD_ENC(aead_key, aead_iv, plaintext, aead_aad)

       if is_final:
           FinalSegmentLength = 4 + AEAD_IV_LEN + len(aead_ciphertext) + AEAD_TAG_LEN
           segment_header = I2BE(FinalSegmentLength, 4)
       else:
           segment_header = I2BE(0xFFFFFFFF, 4)

       EncryptedSegment = segment_header || aead_iv || aead_ciphertext || tag
       return (State, EncryptedSegment)
    ```
    */
    pub fn encrypt_segment(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<()> {
        if is_final {
            if plaintext.len() > self.get_parameter_spec().get_plaintext_segment_length() {
                return Err(Error::InvalidInput);
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() {
                return Err(Error::SegmentOverflow);
            }
            let output_size: u32 = self
                .get_size_of_output(plaintext.len())
                .expect("This is safe because we have already checked the input length")
                .try_into()
                .expect("This is safe because we know the max size of a segment can fit in u32");
            ciphertext[0..SEGMENT_LENGTH_PREFIX_LENGTH].copy_from_slice(&output_size.to_be_bytes());
        } else {
            if plaintext.len() != self.get_parameter_spec().get_plaintext_segment_length() {
                return Err(Error::InvalidInput);
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() - 1 {
                return Err(Error::SegmentOverflow);
            }
            ciphertext[0..SEGMENT_LENGTH_PREFIX_LENGTH]
                .copy_from_slice(&INTERNAL_SEGMENT_PREFIX.to_be_bytes());
        }
        if ciphertext.len() != self.get_size_of_output(plaintext.len())? {
            return Err(Error::InvalidInput);
        }
        let aead_key = self.core.get_epoch_key(segment_number);
        let aad = self.core.build_segment_aad(segment_number, is_final);
        self.core.encrypt(
            &aead_key,
            plaintext,
            &aad,
            &mut ciphertext[SEGMENT_LENGTH_PREFIX_LENGTH..],
        );

        Ok(())
    }

    pub fn get_size_of_output(&self, input_len: usize) -> Result<usize> {
        if input_len
            > self
                .core
                .message_key
                .get_parameters()
                .get_plaintext_segment_length()
        {
            return Err(Error::InvalidInput);
        }
        Ok(input_len
            + self
                .core
                .message_key
                .get_parameters()
                .get_segment_overhead())
    }
}

/**
 * Exposes the FLOE random-access decryption APIs.
 *
 * <div class="warning">The random-access APIs do not directly protect you against truncation attacks
 * or prevent you from incorrectly encrypting the same segment multiple times.</div>
 */
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FloeDecryptor {
    core: CryptoCore,
}

impl FloeDecryptor {
    /**
    Creates a new instance of [FloeDecryptor].

    Corresponds to `startDecryption` from the specification
    */
    /*
    ```plain
       startDecryption(key, aad, header) -> State
           EncodedParams = PARAM_ENCODE(params)
           assert(len(header) == FLOE_IV_LEN + len(EncodedParams) + 32)

           (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
           assert(HeaderParams == EncodedParams)

           ExpectedHeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:")
           if ctEq(ExpectedHeaderTag, HeaderTag) == FALSE: // Must be constant time
               throw("Invalid Header Tag")

           MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
           State = {MessageKey, iv, aad}
           return State
       ```
    */
    pub fn new(key: &FloeKey, aad: &[u8], header: &[u8]) -> Result<Self> {
        let params = &key.get_parameters();
        // assert(len(header) == FLOE_IV_LEN + len(EncodedParams) + 32)
        if header.len() != params.get_header_length() {
            return Err(Error::BadHeader);
        }
        // EncodedParams = PARAM_ENCODE(params)
        let expected_encoded = params.get_encoded();

        // (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
        // assert(HeaderParams == EncodedParams)
        // This does not need to be constant time because encryption *parameters* are considered to be public data in the security model.
        if expected_encoded != header[0..expected_encoded.len()] {
            return Err(Error::BadHeader);
        }
        // (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
        let floe_iv =
            &header[expected_encoded.len()..expected_encoded.len() + params.get_iv_length()];
        // (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
        let tag = &header[expected_encoded.len() + params.get_iv_length()..];

        // ExpectedHeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:")
        let expected_tag = &key
            .derive_key(floe_iv, aad, FloePurpose::HeaderTag, HEADER_TAG_LENGTH)
            .key;

        // if ctEq(ExpectedHeaderTag, HeaderTag) == FALSE: // Must be constant time
        //        throw("Invalid Header Tag")
        // This next comparison *must* be constant time
        let tag_valid: bool = expected_tag.ct_eq(tag).into();
        if !tag_valid {
            return Err(Error::BadHeaderTag);
        }

        // MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
        let message_key = key.derive_key(
            floe_iv,
            aad,
            FloePurpose::MessageKey,
            params.get_hash().get_length(),
        );
        // State = {MessageKey, iv, aad}
        let core = CryptoCore::new(message_key, floe_iv.to_owned(), aad.to_owned())?;

        // return State
        Ok(Self { core })
    }

    pub fn get_parameter_spec(&self) -> crate::FloeParameterSpec {
        self.core.message_key.get_parameters()
    }

    /**
        Decrypts a single FLOE segment with an index of `position_number`.

        The inputs `segment_number` and `is_final` must exactly match those of the corresponding [FloeEncryptor::encrypt_segment] call.

        Corresponds to `decryptSegment` from the specification
    */
    /*
        ```plain
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
        ```
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
                return Err(Error::MalformedSegment);
            }
            let parsed_len = u32::from_be_bytes(
                ciphertext[..SEGMENT_LENGTH_PREFIX_LENGTH]
                    .try_into()
                    .expect("This is safe because SEGMENT_LENGTH_PREFIX_LENGTH is the proper length for u32"),
            ) as usize;
            if parsed_len != ciphertext.len() {
                return Err(Error::MalformedSegment);
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() {
                return Err(Error::SegmentOverflow);
            }
        } else {
            if ciphertext.len() != self.get_parameter_spec().get_encrypted_segment_length() {
                return Err(Error::MalformedSegment);
            }
            let parsed_len = u32::from_be_bytes(
                ciphertext[..SEGMENT_LENGTH_PREFIX_LENGTH]
                    .try_into()
                    .expect("This is safe because SEGMENT_LENGTH_PREFIX_LENGTH is the proper length for u32"),
            );
            if parsed_len != INTERNAL_SEGMENT_PREFIX {
                return Err(Error::MalformedSegment);
            }
            if segment_number >= self.get_parameter_spec().get_aead().get_max_segments() - 1 {
                return Err(Error::SegmentOverflow);
            }
        }
        if ciphertext.len() != plaintext.len() + self.get_parameter_spec().get_segment_overhead() {
            return Err(Error::InvalidInput);
        }
        let aead_key = self.core.get_epoch_key(segment_number);
        let aad = self.core.build_segment_aad(segment_number, is_final);
        self.core.decrypt(
            &aead_key,
            &ciphertext[SEGMENT_LENGTH_PREFIX_LENGTH..],
            &aad,
            plaintext,
        )?;
        Ok(())
    }

    pub fn get_size_of_output(&self, input_len: usize) -> Result<usize> {
        let overhead = self
            .core
            .message_key
            .get_parameters()
            .get_segment_overhead();
        if input_len < overhead {
            return Err(Error::InvalidInput);
        }
        Ok(input_len - overhead)
    }
}
