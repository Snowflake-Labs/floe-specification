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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class TestUtils {
    final static SecureRandom RND = new SecureRandom();
    final static boolean OUTPUT_KATS = false;

    static int be2i(byte[] buf, int offset, int len) {
        final ByteBuffer buff = ByteBuffer.wrap(buf, offset, len);
        switch (len) {
            case 1:
                return buff.get() & 0xFF;
            case 2:
            return buff.getShort() & 0xFFFF;
            case 4:
                return buff.getInt();
            default:
                throw new IllegalArgumentException("Invalid length");
        }
    }

    // KAT here and elsewhere is a "Known Answer Test" also commonly called a "Test Vector"
    static String[] loadKatsFromFile(String katName) throws IOException{
        final String plaintextHex;
        try (InputStream is = TestUtils.class.getClassLoader().getResourceAsStream("kats/" + katName + "_pt.txt")) {
            plaintextHex = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        final String ciphertextHex;
        try (InputStream is = TestUtils.class.getClassLoader().getResourceAsStream("kats/" + katName + "_ct.txt")) {
            ciphertextHex = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        return new String[] {ciphertextHex, plaintextHex};
    }

    // KAT here and elsewhere is a "Known Answer Test" also commonly called a "Test Vector"
    static void decryptKat(final FloeParameterSpec p, byte[] key, byte[] aad, String ciphertextHex, String plaintextHex) throws Exception {
        final byte[] ciphertext = Hex.decodeHex(ciphertextHex);
        final byte[] plaintext = Hex.decodeHex(plaintextHex);
        SequentialDecryptor decryptor = Floe.getInstance(p).createDecryptor(new SecretKeySpec(key, p.getAead().getJceKeyAlg()), aad, ciphertext);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int offset = p.getHeaderLen(); offset < ciphertext.length; offset += p.getEncryptedSegmentLength()) {
            byte[] segment;
            if (offset + p.getEncryptedSegmentLength() >= ciphertext.length) {
                segment = Arrays.copyOfRange(ciphertext, offset, ciphertext.length);
                baos.write(decryptor.processLastSegment(segment));
            } else {
                segment = Arrays.copyOfRange(ciphertext, offset, offset + p.getEncryptedSegmentLength());
                baos.write(decryptor.processSegment(segment));
            }
        }
        assertTrue(decryptor.isDone());
        assertArrayEquals(plaintext, baos.toByteArray());
    }

        static void decryptKatRandomAccess(final FloeParameterSpec p, byte[] key, byte[] aad, String ciphertextHex, String plaintextHex) throws Exception {
        final byte[] ciphertext = Hex.decodeHex(ciphertextHex);
        final byte[] plaintext = Hex.decodeHex(plaintextHex);
        Floe.RandomAccessDecryptor decryptor = Floe.getInstance(p).startDecryption(new SecretKeySpec(key, p.getAead().getJceKeyAlg()), aad, ciphertext);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long counter = 0;
        byte[] segment = new byte[p.getPlaintextSegmentLen()];
        for (int offset = p.getHeaderLen(); offset < ciphertext.length; offset += p.getEncryptedSegmentLength()) {
            final int inputLength;
            final boolean isFinal;
            if (offset + p.getEncryptedSegmentLength() >= ciphertext.length) {
                inputLength = ciphertext.length - offset;
                isFinal = true;
            } else {
                inputLength = p.getEncryptedSegmentLength();
                isFinal = false;
            }
            final int written = decryptor.decryptSegment(ciphertext, offset, inputLength, segment, 0, counter, isFinal);
            counter++;
            baos.write(segment, 0, written);
        }
        assertArrayEquals(plaintext, baos.toByteArray());
    }
}
