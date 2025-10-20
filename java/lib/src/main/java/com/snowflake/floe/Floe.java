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
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Floe {
    public static final FloeParameterSpec GCM256_IV256_4K = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 4 * 1024, 32);
    public static final FloeParameterSpec GCM256_IV256_1M = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 1024 * 1024, 32);
    private static final byte[] INTERNAL_SEGMENT_HEADER = {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};

    private static final byte[] DEK_PURPOSE = "DEK:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HEADER_TAG_PURPOSE = "HEADER_TAG:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE_KEY_PURPOSE = "MESSAGE_KEY:".getBytes(StandardCharsets.UTF_8);
    private static final byte[] EMPTY_ARRAY = new byte[0];

    private final ThreadLocal<SecureRandom> random;
    private final FloeParameterSpec params;
    private final int segmentPlaintextOverhead;

    public static Floe getInstance(final FloeParameterSpec params) {
        return new Floe(params, null);
    }

    public static Floe getInstance(final FloeParameterSpec params, SecureRandom rndOverride) {
        return new Floe(params, rndOverride);
    }

    private Floe(final FloeParameterSpec params, SecureRandom rndOverride) {
        this.params = params;
        segmentPlaintextOverhead = 4 + params.getAead().getNonceLength() + params.getAead().getTagLength();
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

    protected byte[] buildSegmentAad(final long segmentNumber, boolean last) {
        final byte[] aad = new byte[9];
        i2be(segmentNumber, 8, aad, 0);
        aad[aad.length - 1] = (byte) (last ? 1 : 0);
        return aad;
    }

    public FloeEncryptingInputStream createEncryptor(final SecretKey key, final byte[] aad, InputStream inputStream, boolean emitHeader) {
        return new FloeEncryptingInputStream(inputStream, key, aad, params, emitHeader);
    }

    public FloeEncryptingOutputStream createEncryptor(final SecretKey key, final byte[] aad, OutputStream outputStream, boolean emitHeader) {
        return new FloeEncryptingOutputStream(outputStream, key, aad, params, emitHeader);
    }

    public SequentialEncryptor createEncryptor(final SecretKey key, final byte[] aad) {
         return new EncryptorImpl(startEncryption(key, aad));
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

    public SequentialDecryptor createDecryptor(final SecretKey key, byte[] aad, byte[] ciphertextPrefix) {
        return new DecryptorImpl(startDecryption(key, aad, ciphertextPrefix));
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

    private abstract class AbstractOnlineImpl {
        protected final FloeRandomAccess randImpl;
        protected long counter = 0;
        protected boolean closed = false;

        private AbstractOnlineImpl(final FloeRandomAccess randImpl) {
            this.randImpl = randImpl;
        }

        public FloeParameterSpec getParameterSpec() {
            return params;
        }

        protected void assertNotClosed() {
            if (closed) {
                throw new IllegalStateException("SequentialEncryptor is closed");
            }
        }

        protected void assertNonTerminalNoOverflow() {
            if (counter == params.getAead().getMaxSegements() - 1) {
                throw new IllegalStateException("Too many segments");
            }
        }

        public boolean isDone() {
            return closed;
        }
    }

    private final class EncryptorImpl extends AbstractOnlineImpl implements SequentialEncryptor {
        final byte[] header;
        private EncryptorImpl(final RandomAccessEncryptor randImpl) {
            super(randImpl);
            header = randImpl.header;
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
            assertNonTerminalNoOverflow();
            final int result = randImpl.encryptSegment(
                plaintext,
                inputOffset,
                params.getPlaintextSegmentLen(),
                ciphertext,
                outputOffset,
                counter,
                false);
            counter++;
            return result;
        }

        @Override
        public int processLastSegment(byte[] plaintext, int inputOffset, int inputLength, byte[] output, int outputOffset) {
            assertNotClosed();
            final int result = randImpl.encryptSegment(
                plaintext,
                inputOffset,
                inputLength,
                output,
                outputOffset,
                counter,
                true);
            closed = true;
            return result;
        }
    }

    final class DecryptorImpl extends AbstractOnlineImpl implements SequentialDecryptor {
        private DecryptorImpl(final RandomAccessDecryptor randImpl) {
            super(randImpl);
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
            // assert State.Counter != 2^32-1 # Prevent overflow
            assertNonTerminalNoOverflow();
            final int result = randImpl.decryptSegment(
                ciphertext,
                inputOffset,
                params.getEncryptedSegmentLength(),
                plaintext,
                outputOffset,
                counter,
                false);
            counter++;
            return result;
        }

        @Override
        public int processLastSegment(byte[] ciphertext, int inputOffset, int inputLength, byte[] plaintext, int outputOffset) {
            assertNotClosed();
            final int result = randImpl.decryptSegment(
                ciphertext,
                inputOffset,
                inputLength,
                plaintext,
                outputOffset,
                counter,
                true);
            closed = true;
            return result;
        }
    }

    private abstract class FloeRandomAccess implements FloeInstance {
        private final SecretKey messageKey;
        private final byte[] floeIv;
        private final byte[] floeAad;
        private final Cipher cipher;
        private final int segmentLengthOffset = 0;
        private final int segmentIvOffset = segmentLengthOffset + 4;
        private final int segmentCiphertextOffset = segmentIvOffset + params.getAead().getNonceLength();

        private FloeRandomAccess(final SecretKey messageKey, final byte[] floeIv, final byte[] floeAad) {
            this.messageKey = messageKey;
            this.floeIv = cloneOrEmpty(floeIv);
            this.floeAad = cloneOrEmpty(floeAad);
            try {
                cipher = Cipher.getInstance(params.getAead().getJceName());
            } catch (final GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }

        @Override
        public FloeParameterSpec getParameterSpec() {
            return params;
        }

        int encryptSegment(
                final byte[] plaintext,
                final int plaintextOffset,
                final int plaintextLength,
                final byte[] ciphertext,
                final int ciphertextOffset,
                final long segmentNumber,
                final boolean isFinal
            ) {
            try {
                assertOffsets(plaintext, plaintextOffset, plaintextLength);
                assertOffsets(ciphertext, ciphertextOffset, plaintextLength + segmentPlaintextOverhead);
                if (isFinal) {
                    if (plaintextLength > params.getPlaintextSegmentLen()) {
                        throw new IllegalArgumentException("Invalid segment length: " + plaintextLength);
                    }
                } else {
                    if (plaintextLength != params.getPlaintextSegmentLen()) {
                        throw new IllegalArgumentException("Invalid segment length: " + plaintextLength);
                    }
                }

                // This would be worth caching
                final SecretKey aeadKey = deriveKey(messageKey, floeIv, floeAad, segmentNumber);
                final byte[] aeadIv = getRandomBytes(params.getAead().getNonceLength());
                final byte[] aeadAad = buildSegmentAad(segmentNumber, isFinal);

                cipher.init(Cipher.ENCRYPT_MODE, aeadKey, new GCMParameterSpec(params.getAead().getTagLength() * 8, aeadIv));
                cipher.updateAAD(aeadAad);
                cipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset + segmentCiphertextOffset);

                System.arraycopy(aeadIv, 0, ciphertext, ciphertextOffset + segmentIvOffset, aeadIv.length);

                if (isFinal) {
                    i2be(plaintextLength + segmentPlaintextOverhead, 4, ciphertext, ciphertextOffset + segmentLengthOffset);
                } else {
                    System.arraycopy(INTERNAL_SEGMENT_HEADER, 0, ciphertext, ciphertextOffset + segmentLengthOffset, 4);
                }

                return plaintextLength + segmentPlaintextOverhead;
            } catch (final GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            }
        }

        int decryptSegment(
            final byte[] ciphertext,
            final int ciphertextOffset,
            final int ciphertextLength,
            final byte[] plaintext,
            final int plaintextOffset,
            final long segmentNumber,
            final boolean isFinal
        ) {
            try {
                assertOffsets(ciphertext, ciphertextOffset, ciphertextLength);
                assertOffsets(plaintext, plaintextOffset, ciphertextLength - segmentPlaintextOverhead);
                if (isFinal) {
                    if (ciphertextLength > params.getEncryptedSegmentLength()) {
                        throw new IllegalArgumentException("Invalid segment length: " + ciphertextLength);
                    }
                    if (ciphertextLength < segmentPlaintextOverhead) {
                        throw new IllegalArgumentException("Invalid segment length: " + ciphertextLength);
                    }
                    final byte[] encodedLength = new byte[4];
                    i2be(ciphertextLength, 4, encodedLength, 0);
                    if (!Arrays.equals(encodedLength, 0, 4, ciphertext, ciphertextOffset, ciphertextOffset + 4)) {
                        throw new IllegalArgumentException("Invalid segment length: " + ciphertextLength + " " + Base64.getEncoder().encodeToString(Arrays.copyOfRange(ciphertext, ciphertextOffset, ciphertextOffset  + 32)));
                    }
                } else {
                    if (ciphertextLength != params.getEncryptedSegmentLength()) {
                        throw new IllegalArgumentException("Invalid segment length: " + ciphertextLength);
                    }
                    if (!Arrays.equals(INTERNAL_SEGMENT_HEADER, 0, 4, ciphertext, ciphertextOffset, ciphertextOffset + 4)) {
                        throw new IllegalArgumentException("Invalid segment length: " + ciphertextLength);
                    }
                }
                // This would be worth caching
                final SecretKey aeadKey = deriveKey(messageKey, floeIv, floeAad, segmentNumber);
                final GCMParameterSpec spec = new GCMParameterSpec(params.getAead().getTagLength() * 8,
                    ciphertext,
                    ciphertextOffset + segmentIvOffset,
                    params.getAead().getNonceLength());
                final byte[] aeadAad = buildSegmentAad(segmentNumber, isFinal);
                cipher.init(Cipher.DECRYPT_MODE, aeadKey, spec);
                cipher.updateAAD(aeadAad);
                return cipher.doFinal(ciphertext, ciphertextOffset + segmentCiphertextOffset, ciphertextLength - segmentCiphertextOffset, plaintext, plaintextOffset);
            } catch (final AEADBadTagException ex) {
                throw new IllegalArgumentException("Bad tag", ex);
            } catch (final GeneralSecurityException ex) {
                throw new IllegalStateException("Unexpected exception", ex);
            } catch (final RuntimeException ex) {
                throw ex;
            }
        }
    }

    public class RandomAccessEncryptor extends FloeRandomAccess {
        private final byte[] header;

        private RandomAccessEncryptor(final SecretKey messageKey, final byte[] floeIv, final byte[] floeAad, final byte[] header) {
            super(messageKey, floeIv, floeAad);
            this.header = header;
        }

        public int encryptSegment(
                final byte[] plaintext,
                final int plaintextOffset,
                final int plaintextLength,
                final byte[] ciphertext,
                final int ciphertextOffset,
                final long segmentNumber,
                final boolean isFinal) {
            return super.encryptSegment(plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset, segmentNumber, isFinal);
        }

        public byte[] getHeader() {
            return header.clone();
        }

        @Override
        public int inputSegmentSize() {
            return getParameterSpec().getPlaintextSegmentLen();
        }

        @Override
        public int outputSegmentSize() {
            return getParameterSpec().getEncryptedSegmentLength();
        }
    }

    public class RandomAccessDecryptor extends FloeRandomAccess {
        private RandomAccessDecryptor(final SecretKey messageKey, final byte[] floeIv, final byte[] floeAad) {
            super(messageKey, floeIv, floeAad);
        }

        public int decryptSegment(
            final byte[] ciphertext,
            final int ciphertextOffset,
            final int ciphertextLength,
            final byte[] plaintext,
            final int plaintextOffset,
            final long segmentNumber,
            final boolean isFinal) {
            return super.decryptSegment(ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset, segmentNumber, isFinal);
        }

        @Override
        public int inputSegmentSize() {
            return getParameterSpec().getEncryptedSegmentLength();
        }

        @Override
        public int outputSegmentSize() {
            return getParameterSpec().getPlaintextSegmentLen();
        }
    }

    public RandomAccessEncryptor startEncryption(final SecretKey floeKey, final byte[] aad) {
        assertValidKey(floeKey, params.getAead());
        // iv = RND(FLOE_IV_LEN)
        final byte[] iv = getRandomBytes(params.getIvLength());
        // HeaderPrefix = PARAM_ENCODE(params) || iv
        final ByteBuffer encodedParams = params.getEncoded();
        final ByteBuffer header = ByteBuffer.allocate(params.getHeaderLen());
        header.put(encodedParams);
        header.put(iv);

        // HeaderTag = FLOE_KDF(key, iv, aad, “HEADER_TAG:”)
        final byte[] headerTag = floe_kdf(floeKey, iv, aad, HEADER_TAG_PURPOSE, 32);
        header.put(headerTag);
        if (header.hasRemaining()) {
            throw new IllegalStateException("Unexpected remaining bytes: " + header.remaining());
        }
        // MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", 32)
        final SecretKey messageKey = new SecretKeySpec(floe_kdf(floeKey, iv, aad, MESSAGE_KEY_PURPOSE, params.getHash().getLength()), "FLOE_MSG_KEY");
        return new RandomAccessEncryptor(messageKey, iv, aad, header.array());
    }

    public RandomAccessDecryptor startDecryption(final SecretKey key, byte[] aad, byte[] ciphertextPrefix) {
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
        return new RandomAccessDecryptor(messageKey, iv, aad);
    }

    private static void assertOffsets(final byte[] array, final int offset, final int length) {
        if (offset < 0 || length < 0) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if ((long) offset + (long) length > array.length) {
            throw new ArrayIndexOutOfBoundsException(String.format("%d + %d ?> %d", offset, length, array.length));
        }
    }
}
