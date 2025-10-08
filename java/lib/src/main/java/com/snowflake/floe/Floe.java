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

package com.snowflake.floe;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Floe {
    public static final FloeParameterSpec GCM256_IV256_4K = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 4 * 1024, 32);
    public static final FloeParameterSpec GCM256_IV256_1M = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 1024 * 1024, 32);
    private static final int INTERNAL_SEGMENT_HEADER = -1;

    private static final byte[] DEK_PURPOSE = "DEK:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HEADER_TAG_PURPOSE = "HEADER_TAG:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE_KEY_PURPOSE = "MESSAGE_KEY:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] EMPTY_ARRAY = new byte[0];

    private final ThreadLocal<SecureRandom> random;
    private final FloeParameterSpec params;

    public static Floe getInstance(final FloeParameterSpec params) {
        return new Floe(params, null);
    }

    public static Floe getInstance(final FloeParameterSpec params, SecureRandom rndOverride) {
        return new Floe(params, rndOverride);
    }

    private Floe(final FloeParameterSpec params, SecureRandom rndOverride) {
        this.params = params;
        if (rndOverride == null) {
            // By default we use thread local secure random for better performance, not for correctness
            random = ThreadLocal.withInitial(SecureRandom::new);
        } else {
            // SecureRandom instances are thread safe
            random = ThreadLocal.withInitial(() -> rndOverride);
        }
    }
    
    private byte[] getRandomBytes(int length) {
        final byte[] result = new byte[length];
        random.get().nextBytes(result);
        return result;
    }

    private static byte[] cloneOrEmpty(byte[] arr) {
        return arr == null ? EMPTY_ARRAY : arr.clone();
    }

    private static void assertValidKey(final SecretKey key, final FloeAead aead) {
        if (key.getFormat().equalsIgnoreCase("RAW")) {
            final byte[] rawKey = key.getEncoded();
            if (rawKey != null) {
                Arrays.fill(rawKey, (byte) 0);
                if (rawKey.length != aead.getKeyLength()) {
                    throw new IllegalArgumentException("FLOE key must have length equal to AEAD key. Was " + rawKey.length + " not " + aead.getKeyLength());
                }
            }
        }
    }

    public FloeEncryptingInputStream createEncryptor(final SecretKey key, final byte[] aad, InputStream inputStream, boolean emitHeader) {
        return new FloeEncryptingInputStream(inputStream, key, aad, params, emitHeader);
    }

    public FloeEncryptingOutputStream createEncryptor(final SecretKey key, final byte[] aad, OutputStream outputStream, boolean emitHeader) {
        return new FloeEncryptingOutputStream(outputStream, key, aad, params, emitHeader);
    }

    public Encryptor createEncryptor(final SecretKey key, final byte[] aad) {
        assertValidKey(key, params.getAead());
        // iv = RND(FLOE_IV_LEN)
        final byte[] iv = getRandomBytes(params.getIvLength());
        // HeaderPrefix = PARAM_ENCODE(params) || iv
        final ByteBuffer encodedParams = params.getEncoded();
        final ByteBuffer header = ByteBuffer.allocate(params.getHeaderLen());
        header.put(encodedParams);
        header.put(iv);

        // HeaderTag = FLOE_KDF(key, iv, aad, “HEADER_TAG:”)
        final byte[] headerTag = floe_kdf(key, iv, aad, HEADER_TAG_PURPOSE, 32);
        header.put(headerTag);
        if (header.hasRemaining()) {
            throw new IllegalStateException("Unexpected remaining bytes: " + header.remaining());
        }
        // MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", 32)
        final SecretKey messageKey = new SecretKeySpec(floe_kdf(key, iv, aad, MESSAGE_KEY_PURPOSE, params.getHash().getLength()), "FLOE_MSG_KEY");
        return new EncryptorImpl(header.array(), iv, aad, messageKey);
    }

    public FloeDecryptingInputStream createDecryptor(final SecretKey key, byte[] aad, InputStream inputStream) {
        return new FloeDecryptingInputStream(inputStream, key, aad, params);
    }

    public FloeDecryptingInputStream createDecryptor(final SecretKey key, byte[] aad, InputStream inputStream, byte[] separateHeader) {
        return new FloeDecryptingInputStream(inputStream, key, aad, params, separateHeader);
    }
    
    public FloeDecryptingOutputStream createDecryptor(final SecretKey key, byte[] aad, OutputStream outputStream) {
        return new FloeDecryptingOutputStream(outputStream, key, aad, params);
    }

    public FloeDecryptingOutputStream createDecryptor(final SecretKey key, byte[] aad, OutputStream outputStream, byte[] separateHeader) {
        return new FloeDecryptingOutputStream(outputStream, key, aad, params, separateHeader);
    }

    public Decryptor createDecryptor(final SecretKey key, byte[] aad, byte[] ciphertextPrefix) {
        assertValidKey(key, params.getAead());
        // EncodedParams = PARAM_ENCODE(params)
        ByteBuffer encodedParams = params.getEncoded();
        // assert len(header) == FLOE_IV_LEN + len(EncodedParams) + 32
        if (ciphertextPrefix.length < params.getHeaderLen()) {
            throw new IllegalArgumentException("Ciphertext prefix too short. Must be of length: " + params.getIvLength() + 4 + " was " + ciphertextPrefix.length);
        }
        ByteBuffer header = ByteBuffer.wrap(ciphertextPrefix, 0, params.getHeaderLen());
        // (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
        final ByteBuffer headerParams = header.limit(encodedParams.remaining()).duplicate();
        header.limit(header.capacity());
        header.position(encodedParams.remaining());
        header.limit(header.capacity() - 32);
        final byte[] iv = new byte[params.getIvLength()];
        header.get(iv);
        header.limit(header.capacity());
        final byte[] headerTag = new byte[32];
        header.get(headerTag);

        // assert HeaderParams == EncodedParams
        if (!encodedParams.equals(headerParams)) {
            throw new IllegalArgumentException("Invalid header parameters");
        }
        // ExpectedHeaderTag = FLOE_KDF(key, iv, aad, “HEADER_TAG:”)
        final byte[] expectedHeaderTag = floe_kdf(key, iv, aad, HEADER_TAG_PURPOSE, 32);
        // assert ExpectedHeaderTag == HeaderTag // Must be constant time
        if (!MessageDigest.isEqual(headerTag, expectedHeaderTag)) {
            throw new IllegalArgumentException("Invalid header tag");
        }
        // MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", 32)
        final SecretKey messageKey = new SecretKeySpec(floe_kdf(key, iv, aad, MESSAGE_KEY_PURPOSE, params.getHash().getLength()), "FLOE_MSG_KEY");
        return new DecryptorImpl(iv, aad, messageKey);
    }
 
    // VisibleForTesting
    static void i2be(final long val, int len, final byte[] buf, int offset) {
        if (val < 0) {
            throw new IllegalArgumentException("Value cannot be negative: " + val);
        }
        if (len == 1) {
            if (val > 255) {
                throw new IllegalArgumentException("Value out of range: " + val);
            }
            buf[offset] = (byte) val;
        } else if (len == 2) {
            if (val > 65535) {
                throw new IllegalArgumentException("Value out of range: " + val);
            }
            buf[offset] = (byte) ((val >> 8) & 0xff);
            buf[offset + 1] = (byte) (val & 0xff);
        } else if (len == 4) {
            buf[offset] = (byte) ((val >> 24) & 0xff);
            buf[offset + 1] = (byte) ((val >> 16) & 0xff);
            buf[offset + 2] = (byte) ((val >> 8) & 0xff);
            buf[offset + 3] = (byte) (val & 0xff);
        } else if (len == 8) {
            buf[offset] = (byte) ((val >> 56) & 0xff);
            buf[offset + 1] = (byte) ((val >> 48) & 0xff);
            buf[offset + 2] = (byte) ((val >> 40) & 0xff);
            buf[offset + 3] = (byte) ((val >> 32) & 0xff);
            buf[offset + 4] = (byte) ((val >> 24) & 0xff);
            buf[offset + 5] = (byte) ((val >> 16) & 0xff);
            buf[offset + 6] = (byte) ((val >> 8) & 0xff);
            buf[offset + 7] = (byte) (val & 0xff);
        } else {
            throw new IllegalArgumentException("Unsupported length: " + len);
        }
    }

    // VisibleForTesting
    static byte[] hkdfExpand(final FloeHash hash, final SecretKey prk, final byte[] info, final int len) {
        if (len < 0 || len > hash.getLength()) {
            throw new IllegalArgumentException("Invalid length: " + len);
        }
        try {
            final Mac hmac = Mac.getInstance(hash.getJceName());
            hmac.init(prk);
            hmac.update(info);
            hmac.update((byte) 1);
            final byte[] result = hmac.doFinal();
            if (len == result.length) {
                return result;
            } else {
                return Arrays.copyOf(result, len);
            }
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unexpected exception", ex);
        }
    }

    // VisibleForTesting
    byte[] floe_kdf(final SecretKey key, final byte[] iv, byte[] aad, final byte[] purpose, int len) {
        if (iv.length != params.getIvLength()) {
            throw new IllegalArgumentException("Invalid IV length: " + iv.length);
        }
        if (aad == null) {
            aad = EMPTY_ARRAY;
        }
        final ByteBuffer encodedParams = params.getEncoded();
        final ByteBuffer info = ByteBuffer.allocate(encodedParams.remaining() + iv.length + aad.length + purpose.length);
        info.put(encodedParams);
        info.put(iv);
        info.put(purpose);
        info.put(aad);
        if (info.hasRemaining()) {
            throw new IllegalStateException("Unexpected remaining bytes: " + info.remaining());
        }
        return hkdfExpand(params.getHash(), key, info.array(), len);
    }

    private SecretKey deriveKey(final SecretKey key, final byte[] iv, final byte[] aad, long segmentNumber) {
        long mask = params.getOverrideRotationMask();
        
        long maskedSegmentNumber = segmentNumber & mask;

        byte[] mergedPurpose = Arrays.copyOf(DEK_PURPOSE, DEK_PURPOSE.length + 8);
        i2be(maskedSegmentNumber, 8, mergedPurpose, DEK_PURPOSE.length);
        byte[] rawKey = floe_kdf(key, iv, aad, mergedPurpose, params.getAead().getKeyLength());
        return new SecretKeySpec(rawKey, params.getAead().getJceKeyAlg());
    }

    private abstract class AbstractImpl implements FloeSegmentProcessor {
        private final byte[] floeIv;
        private final byte[] aad;
        protected final SecretKey key;
        private final Cipher cipher;
        private long lastMaskedCounter = -1;
        private SecretKey cachedKey = null;
        protected long counter = 0;
        protected boolean closed = false;

        private AbstractImpl(final byte[] iv, final byte[] aad, final SecretKey key) {
            this.floeIv = iv;
            this.aad = cloneOrEmpty(aad);
            this.key = key;
            try {
                this.cipher = Cipher.getInstance(params.getAead().getJceName());
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }

        @Override
        public FloeParameterSpec getParameterSpec() {
            return params;
        }

        protected void assertNotClosed() {
            if (closed) {
                throw new IllegalStateException("Encryptor is closed");
            }
        }

        protected void assertNonTerminalNoOverflow() {
            if (counter == params.getAead().getMaxSegements() - 1) {
                throw new IllegalStateException("Too many segments");
            }
        }
        protected byte[] buildSegmentAad(boolean last) {
            final byte[] aad = new byte[9];
            i2be(counter, 8, aad, 0);
            aad[aad.length - 1] = (byte) (last ? 1 : 0);
            return aad;
        }

        private SecretKey getCurrentKey() {
            return deriveKey(key, floeIv, aad, counter);
        }
    
        protected Cipher prepCipher(final int cipherMode, final AlgorithmParameterSpec paramSpec, final boolean isLast) {
            try {
                final long maskedCounter = counter & params.getOverrideRotationMask();
                final SecretKey key;
                final boolean newKey = maskedCounter != lastMaskedCounter;
                if (newKey) {
                    key = getCurrentKey();
                    cachedKey = key;
                    lastMaskedCounter = maskedCounter;
                } else {
                    key = cachedKey;
                }

                if (paramSpec != null) {
                    cipher.init(cipherMode, key, paramSpec);
                } else {
                    cipher.init(cipherMode, key);
                }
                
                final byte[] aad = buildSegmentAad(isLast);
                cipher.updateAAD(aad);
                return cipher;
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }

        }

        @Override
        public boolean isDone() {
            return closed;
        }
    }

    private final class EncryptorImpl extends AbstractImpl implements Encryptor {
        private final byte[] header;

        private EncryptorImpl(final byte[] header, final byte[] iv, final byte[] aad, final SecretKey key) {
            super(iv, aad, key);
            this.header = header;
        }

        @Override
        public byte[] getHeader() {
            return header.clone();
        }

        @Override
        public int inputSegmentSize() {
            return params.getPlaintextSegmentLen();
        }

        @Override
        public int outputSegmentSize() {
            return params.getEncryptedSegmentLength();
        }

        @Override
        public int processSegment(byte[] plaintext, int inputOffset, byte[] ciphertext, int outputOffset) {
            assertNotClosed();
            // assert len(plaintext) == ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4
            if (plaintext.length - inputOffset < params.getPlaintextSegmentLen()) {
                throw new ArrayIndexOutOfBoundsException("Insufficient input size: " + plaintext.length);
            }
            if (ciphertext.length - outputOffset < params.getEncryptedSegmentLength()) {
                throw new ArrayIndexOutOfBoundsException("Insufficient output size: " + ciphertext.length);
            }
            // assert State.Counter != 2^32-1 # Prevent overflow
            assertNonTerminalNoOverflow();
            try {
                final byte[] iv = getRandomBytes(params.getAead().getNonceLength());
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                final Cipher cipher = prepCipher(Cipher.ENCRYPT_MODE, spec, false);
                final ByteBuffer result = ByteBuffer.wrap(ciphertext, outputOffset, params.getEncryptedSegmentLength());
                result.putInt(INTERNAL_SEGMENT_HEADER);
                result.position(result.position() + params.getAead().getNonceLength());
                final ByteBuffer plaintextBuf = ByteBuffer.wrap(plaintext, inputOffset, params.getPlaintextSegmentLen());
                
                // (aead_ciphertext, tag) = AEAD_ENC(State.AeadKey, aead_iv, plaintext, aead_aad)
                final int ctLen = cipher.doFinal(plaintextBuf, result);
                if (ctLen != plaintext.length + params.getAead().getTagLength()) {
                    throw new IllegalStateException("Unexpected output length: " + ctLen);
                }
                if (plaintextBuf.hasRemaining()) {
                    throw new IllegalStateException("Unexpected remaining bytes: " + plaintextBuf.remaining());
                }
                if (result.hasRemaining()) {
                    throw new IllegalStateException("Unexpected remaining bytes: " + result.remaining());
                }
                
                // aead_iv = RND(AEAD_IV_LEN)
                // final byte[] iv = cipher.getIV();
                if (iv.length != params.getAead().getNonceLength()) {
                    throw new IllegalStateException("Unexpected IV length: " + iv.length);
                }

                // EncryptedSegment = 0xFFFFFFFF || aead_iv || aead_ciphertext || tag
                result.position(0);
                result.putInt(-1);
                result.put(iv);
                // State.Counter++
                counter++;
                return params.getEncryptedSegmentLength();
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }

        @Override
        public int processLastSegment(byte[] plaintext, int inputOffset, int inputLength, byte[] output, int outputOffset) {
            assertNotClosed();
            // assert len(plaintext) >= 0
            //   NOP in Java
            // assert len(plaintext) <= ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4
            if (inputLength > params.getPlaintextSegmentLen()) {
                throw new IllegalArgumentException("Invalid segment length: " + plaintext.length);
            }

            try {
                final byte[] iv = getRandomBytes(params.getAead().getNonceLength());
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                final Cipher cipher = prepCipher(Cipher.ENCRYPT_MODE, spec, true);
                // FinalSegementLength = len(plaintext) + 4 + AEAD_IV_LEN + AEAD_TAG_LEN
                final int finalSegmentLength = inputLength + 4 + params.getAead().getNonceLength() + params.getAead().getTagLength();
                final ByteBuffer result = ByteBuffer.wrap(output, outputOffset, finalSegmentLength);
                result.putInt(finalSegmentLength);
                result.position(result.position() + params.getAead().getNonceLength());
                final ByteBuffer plaintextBuf = ByteBuffer.wrap(plaintext, inputOffset, inputLength);
                // (aead_ciphertext, tag) = AEAD_ENC(State.AeadKey, aead_iv, plaintext, aead_aad)	
                final int ctLen = cipher.doFinal(plaintextBuf, result);
                if (ctLen != inputLength + params.getAead().getTagLength()) {
                    throw new IllegalStateException("Unexpected output length: " + ctLen);
                }
                if (plaintextBuf.hasRemaining()) {
                    throw new IllegalStateException("Unexpected remaining bytes: " + plaintextBuf.remaining());
                }
                if (result.hasRemaining()) {
                    throw new IllegalStateException("Unexpected remaining bytes: " + result.remaining());
                }
                // aead_iv = RND(AEAD_IV_LEN)
                // final byte[] iv = cipher.getIV();
                if (iv.length != params.getAead().getNonceLength()) {
                    throw new IllegalStateException("Unexpected IV length: " + iv.length);
                }
                // EncryptedSegment = I2BE(FinalSegementLength, 4) || aead_iv || aead_ciphertext || tag
                result.position(0);
                result.putInt(finalSegmentLength);
                result.put(iv);

                closed = true;
                return finalSegmentLength;
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }
    }

    final class DecryptorImpl extends AbstractImpl implements Decryptor {
        private DecryptorImpl(final byte[] iv, final byte[] aad, final SecretKey key) {
            super(iv, aad, key);
        }

        @Override
        public FloeParameterSpec getParameterSpec() {
            return params;
        }

        @Override
        public int inputSegmentSize() {
            return params.getEncryptedSegmentLength();
        }

        @Override
        public int outputSegmentSize() {
            return params.getPlaintextSegmentLen();
        }
        
        @Override
        public int processSegment(byte[] ciphertext, int inputOffset, byte[] plaintext, int outputOffset) {
            assertNotClosed();
            // assert len(EncryptedSegment) == ENC_SEG_LEN
            if (ciphertext.length - inputOffset < params.getEncryptedSegmentLength()) {
                throw new ArrayIndexOutOfBoundsException("Insufficient input size: " + ciphertext.length);
            }
            if (plaintext.length - outputOffset < params.getPlaintextSegmentLen()) {
                throw new ArrayIndexOutOfBoundsException("Insufficient output size: " + plaintext.length);
            }
            final ByteBuffer ciphertextBuf = ByteBuffer.wrap(ciphertext, inputOffset, params.getEncryptedSegmentLength());
            final int segmentLength = ciphertextBuf.getInt();
            // assert BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF
            if (segmentLength != INTERNAL_SEGMENT_HEADER) {
                throw new IllegalArgumentException("Invalid segment length: " + segmentLength);
            }
            // assert State.Counter != 2^32-1 # Prevent overflow
            assertNonTerminalNoOverflow();
            try {
                // (aead_iv, aead_ciphertext, tag) = SPLIT(EncryptedSegment[4:], AEAD_IV_LEN, AEAD_TAG_LEN)
                final int ivOffset = inputOffset + 4;
                final int ivLen = params.getAead().getNonceLength();
                final int aeadCiphertextOffset = ivOffset + ivLen;
                final int aeadCiphertextLen = params.getEncryptedSegmentLength() - ivLen - 4;

                final AlgorithmParameterSpec paramSpec = params.getAead().buildSpec(ciphertext, ivOffset);
                final Cipher cipher = prepCipher(Cipher.DECRYPT_MODE, paramSpec, false);
                // Plaintext = AEAD_DEC(State.AeadKey, aead_iv, aead_ciphertext, aead_aad)
                // assert Plaintext != FAIL
                cipher.doFinal(ciphertext, aeadCiphertextOffset, aeadCiphertextLen, plaintext, outputOffset);
                // State.Counter++
                counter++;
                // return Plaintext
                return params.getPlaintextSegmentLen();
            } catch (final AEADBadTagException ex) {
                throw new IllegalArgumentException("Bad tag", ex);
            } catch (final GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }

        @Override
        public int processLastSegment(byte[] ciphertext, int inputOffset, int inputLength, byte[] plaintext, int outputOffset) {
            if (closed) {
                throw new IllegalStateException("Encryptor is closed");
            }
            // assert len(EncryptedSegment) >= AEAD_IV_LEN + AEAD_TAG_LEN + 4
            if (inputLength < params.getAead().getNonceLength() + params.getAead().getTagLength() + 4) {
                throw new IllegalArgumentException("Invalid segment length: " + inputLength);
            }
            // assert len(EncryptedSegment) <= ENC_SEG_LEN
            if (inputLength > params.getEncryptedSegmentLength()) {
                throw new IllegalArgumentException("Invalid segment length: " + inputLength);
            }
            // assert BE2I(EncryptedSegment[:4]) == len(EncryptedSegment)
            final ByteBuffer ciphertextBuf = ByteBuffer.wrap(ciphertext, inputOffset, inputLength);
            final int segmentLength = ciphertextBuf.getInt();
            if (segmentLength != inputLength) {
                throw new IllegalArgumentException("Segment length " + segmentLength + " does not match provided " + inputLength);
            }

            // (aead_iv, aead_ciphertext, tag) = SPLIT(EncryptedSegment[:4], AEAD_IV_LEN, AEAD_TAG_LEN)
            final int ivOffset = inputOffset + 4;
            final int ivLen = params.getAead().getNonceLength();
            final int aeadCiphertextOffset = ivOffset + ivLen;
            final int aeadCiphertextLen = inputLength - ivLen - 4;
            try {
                final AlgorithmParameterSpec paramSpec = params.getAead().buildSpec(ciphertext, ivOffset);
                final Cipher cipher = prepCipher(Cipher.DECRYPT_MODE, paramSpec, true);
                // Plaintext = AEAD_DEC(State.AeadKey, aead_iv, aead_ciphertext, aead_aad)
                // assert Plaintext != FAIL
                int result = cipher.doFinal(ciphertext, aeadCiphertextOffset, aeadCiphertextLen, plaintext, outputOffset);
                closed = true;
                // return Plaintext
                return result;
            } catch (final AEADBadTagException ex) {
                throw new IllegalArgumentException("Bad tag", ex);
            } catch (final GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }
    }
}
