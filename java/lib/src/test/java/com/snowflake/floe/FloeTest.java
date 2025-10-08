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

import static com.snowflake.floe.TestUtils.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class FloeTest {
    @Test
    public void i2beTest1() {
        byte[] buf = new byte[3];
        for (int val = 0; val < 256; val++) {
            Arrays.fill(buf, (byte) 0);
            Floe.i2be(val, 1, buf, 1);
            assertEquals(buf[0], 0);
            assertEquals(buf[1], (byte) val);
            assertEquals(buf[2], 0);

            assertEquals(val, be2i(buf, 1, 1));
        }
    }

    @Test
    public void i2beTest2() {
        byte[] buf = new byte[4];
        for (int val = 0; val < (1 << 15); val++) {
            Arrays.fill(buf, (byte) 0);
            Floe.i2be(val, 2, buf, 1);
            assertEquals(buf[0], 0);
            
            int decoded = (buf[1] & 0xff) << 8 | (buf[2] & 0xff);
            assertEquals(val, decoded);

            assertEquals(buf[3], 0);

            assertEquals(val, be2i(buf, 1, 2));
        }
    }

    @Test
    public void i2beTest4() {
        int[] testCases = {0, 1, 128, 256, Short.MAX_VALUE, Short.MAX_VALUE + 1, Integer.MAX_VALUE};
        byte[] buf = new byte[6];
        for (int val : testCases) {
            Arrays.fill(buf, (byte) 0);
            Floe.i2be(val, 4, buf, 1);
            assertEquals(buf[0], 0);
            
            int decoded = (buf[1] & 0xff) << 24 | (buf[2] & 0xff) << 16 | (buf[3] & 0xff) << 8 | (buf[4] & 0xff);
            assertEquals(val, decoded);
            assertEquals(val, be2i(buf, 1, 4));

            assertEquals(buf[5], 0);
        }
    }

    @Test
    public void smoke_GCM256_IV256_64() throws Exception{
        FloeParameterSpec p = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 64, 32);
        testParams(p, 2, 3, "GCM256_IV256_64");
    }

    @Test
    public void smoke_GCM256_IV256_4K() throws Exception{
        testParams(Floe.GCM256_IV256_4K, 2, 3, "GCM256_IV256_4K");
    }

    @Test
    public void smoke_GCM256_IV256_1M() throws Exception{
        testParams(Floe.GCM256_IV256_1M, 2, 3, "GCM256_IV256_1M");
    }

    @Test
    public void smoke_rotation() throws Exception {
        FloeParameterSpec p = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 40, 32, -4);
        testParams(p, 10, 3, "rotation");
    }

    @Test
    public void smoke_lastSegAligned() throws Exception {
        FloeParameterSpec p = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 40, 32);
        testParams(p, 2, p.getPlaintextSegmentLen(), "lastSegAligned");
    }

    @Test
    public void smoke_lastSegEmpty() throws Exception {
        FloeParameterSpec p = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 40, 32);
        testParams(p, 2, 0, "lastSegEmpty");
    }

    private static void testParams(final FloeParameterSpec p, int segCount, int lastSegSize, String katName) throws Exception{
        final SecretKey key = new SecretKeySpec(new byte[p.getAead().getKeyLength()], "FLOE");
        final byte[] plaintext = new byte[segCount * p.getPlaintextSegmentLen() + lastSegSize];
        RND.nextBytes(plaintext);
        final byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);

        Encryptor encryptor = Floe.getInstance(p).createEncryptor(key, aad);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(encryptor.getHeader());

        for (int offset = 0; offset < plaintext.length; offset += p.getPlaintextSegmentLen()) {
            byte[] segment;
            if (plaintext.length - offset <= lastSegSize) {
                segment = Arrays.copyOfRange(plaintext, offset, plaintext.length);
                baos.write(encryptor.processLastSegment(segment));
            } else {
                segment = Arrays.copyOfRange(plaintext, offset, offset + p.getPlaintextSegmentLen());
                baos.write(encryptor.processSegment(segment));
            }
        }
        if (!encryptor.isDone()) {
            // We've processed the entire plaintext, we need a final empty segment
            assertEquals(lastSegSize, 0, "Test error. Check test logic.");
            baos.write(encryptor.processLastSegment(new byte[0]));
        }
        byte[] ciphertext = baos.toByteArray();
        // System.out.format("KeyLen %d, IvLen %d, SegLen %d\n", p.getAead().getKeyLength(), p.getIvLength(), p.getSegmentLength());
        // System.out.println("Plaintext:  " + Hex.encodeHexString(plaintext));
        // System.out.println("Ciphertext: " + Hex.encodeHexString(ciphertext));
        Decryptor decryptor = Floe.getInstance(p).createDecryptor(key, aad, ciphertext);
        baos = new ByteArrayOutputStream();
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
        assertEquals(p, FloeParameterSpec.fromEncoded(ByteBuffer.wrap(ciphertext)));

        if (OUTPUT_KATS) {
            final File ptFile = new File("src/test/resources/java_" + katName + "_pt.txt");
            final File ctFile = new File("src/test/resources/java_" + katName + "_ct.txt");
            try (FileWriter pWriter = new FileWriter(ptFile); FileWriter cWriter = new FileWriter(ctFile)) {
                pWriter.write(Hex.encodeHexString(plaintext));
                cWriter.write(Hex.encodeHexString(ciphertext));
            }
            System.err.println("Wrote plaintext to " + ptFile.getAbsolutePath());
            System.err.println("Wrote ciphertext to " + ctFile.getAbsolutePath());
        }
    }

    private static class CountingSecRandom extends SecureRandom {
        byte currVal = 0;

        @Override
        public void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = currVal++;
            }
        }
    }

    @Test
    public void rndOverride() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(params, new CountingSecRandom());
        final byte[] ptSeg = new byte[params.getPlaintextSegmentLen()];

        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        byte[] header = encryptor.getHeader();
        byte[] firstCt = encryptor.processSegment(ptSeg);
        byte[] lastCt = encryptor.processLastSegment(ptSeg);

        Decryptor decryptor = floe.createDecryptor(key, new byte[0], header);
        
        assertArrayEquals(ptSeg, decryptor.processSegment(firstCt));
        assertArrayEquals(ptSeg, decryptor.processLastSegment(lastCt));
        // Check that the generated IV is incrementing bytes
        byte[] iv = new byte[params.getIvLength()];
        System.arraycopy(header, params.getEncoded().remaining(), iv, 0, iv.length);
        byte[] expectedIV = new byte[params.getIvLength()];
        byte rndVal = 0;
        for (int i = 0; i < iv.length; i++) {
            expectedIV[i] = (byte) rndVal++;
        }
        assertArrayEquals(expectedIV, iv);
        // Check first segment IV
        iv = new byte[params.getAead().getNonceLength()];
        System.arraycopy(firstCt, 4, iv, 0, iv.length);
        expectedIV = new byte[iv.length];
        for (int i = 0; i < iv.length; i++) {
            expectedIV[i] = (byte) rndVal++;
        }
        assertArrayEquals(expectedIV, iv);
    }

    @Test
    public void emptyPT() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        final byte[] header = encryptor.getHeader();
        final byte[] lastSegmentCt = encryptor.processLastSegment(new byte[0]);


        Decryptor decryptor = floe.createDecryptor(key, new byte[0], header);

        final byte[] decrypted = decryptor.processLastSegment(lastSegmentCt);
        assertEquals(0, decrypted.length);
    }

    @Test
    public void badParams() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        final byte[] header = encryptor.getHeader();
        header[0] = (byte) (header[0] - 1);

        assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(key, new byte[0], header));
    }

    @Test
    public void badIv() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        final byte[] header = encryptor.getHeader();
        header[16] ^= 0x01;

        assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(key, new byte[0], header));
    }

    @Test
    public void badHeaderTag() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        final byte[] header = encryptor.getHeader();
        header[header.length - 1] ^= 0x01;

        assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(key, new byte[0], header));
    }

    @Test
    public void segmentAligned() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        final byte[] ptSeg = new byte[Floe.GCM256_IV256_4K.getPlaintextSegmentLen()];

        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        byte[] header = encryptor.getHeader();
        byte[] firstCt = encryptor.processSegment(ptSeg);
        byte[] lastCt = encryptor.processLastSegment(ptSeg);

        Decryptor decryptor = floe.createDecryptor(key, new byte[0], header);
        
        assertArrayEquals(ptSeg, decryptor.processSegment(firstCt));
        assertArrayEquals(ptSeg, decryptor.processLastSegment(lastCt));
    }

    @Test
    public void segmentAlignedTrailingEmpty() throws Exception {
        SecretKey key = new SecretKeySpec(new byte[32], "FLOE");
        Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        final byte[] ptSeg = new byte[Floe.GCM256_IV256_4K.getPlaintextSegmentLen()];

        Encryptor encryptor = floe.createEncryptor(key, new byte[0]);
        byte[] header = encryptor.getHeader();
        byte[] firstCt = encryptor.processSegment(ptSeg);
        byte[] lastCt = encryptor.processLastSegment(new byte[0]);

        Decryptor decryptor = floe.createDecryptor(key, new byte[0], header);
        
        assertArrayEquals(ptSeg, decryptor.processSegment(firstCt));
        assertArrayEquals(new byte[0], decryptor.processLastSegment(lastCt));
    }

    public static List<Arguments> katTestParameters() {
        final String[] sources = new String[]{"go", "java", "pub_java", "cpp", "rust"};
        final List<Arguments> result = new ArrayList<>();
        final FloeParameterSpec smallSpec = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 64, 32);
        final FloeParameterSpec rotationSpec = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 40, 32, -4);
        for (String source : sources) {
            result.add(Arguments.of(Floe.GCM256_IV256_4K, source + "_GCM256_IV256_4K"));
            result.add(Arguments.of(Floe.GCM256_IV256_1M, source + "_GCM256_IV256_1M"));
            result.add(Arguments.of(smallSpec, source + "_GCM256_IV256_64"));
            result.add(Arguments.of(rotationSpec, source + "_rotation"));
        }
        // There are a few Java generated only KATs
        FloeParameterSpec finalSegmentParams = new FloeParameterSpec(FloeAead.AES_GCM_256, FloeHash.SHA384, 40, 32);
        result.add(Arguments.of(finalSegmentParams, "java_lastSegAligned"));
        result.add(Arguments.of(finalSegmentParams, "java_lastSegEmpty"));
        return result;
    }

    @ParameterizedTest
    @MethodSource("katTestParameters")
    public void testKat(final FloeParameterSpec spec, final String katName) throws Exception {
        byte[] key = new byte[spec.getAead().getKeyLength()];

        byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);
        String[] kats = loadKatsFromFile(katName);
        decryptKat(spec, key, aad, kats[0], kats[1]);
    }

    @ParameterizedTest
    @EnumSource(FloeAead.class)
    public void properKeySize(final FloeAead aead) throws Exception {
        final FloeParameterSpec spec = new FloeParameterSpec(aead, FloeHash.SHA384, 4096, 32);
        final Floe floe = Floe.getInstance(Floe.GCM256_IV256_4K);
        
        final SecretKey properKey = new SecretKeySpec(new byte[aead.getKeyLength()], "FLOE");
        final SecretKey longKey = new SecretKeySpec(new byte[aead.getKeyLength() + 1], "FLOE");

        // We want no exception
        final Encryptor encryptor = floe.createEncryptor(properKey, null);
        assertNotNull(encryptor);

        // Wrong size, should fail
        assertThrows(IllegalArgumentException.class, () -> floe.createEncryptor(longKey, null));

        // Check Decryption with wrong size. Header must come from proper size.
        assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(longKey, null, encryptor.getHeader()));

    }
}
