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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

public class StreamTest {
    private static final int[] CHUNK_SIZES = new int[]{1, 16, 1024, 1025, 4095, 4096, 4097, 1000000};

    @Test
    public void encryptOutputEmpty() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[0];
  
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
            eos.close();
            assertTrue(eos.isDone());
        }
        final byte[] ct = out.toByteArray();
        final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
        assertArrayEquals(pt, decrypted);
    }
    @Test
    public void encryptOutputSmokeAligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
                eos.close();
                assertTrue(eos.isDone());
            }
            final byte[] ct = out.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptOutputSmokeUnaligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4 + 47];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
                eos.close();
                assertTrue(eos.isDone());
            }
            final byte[] ct = out.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptOutputSmall() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[47];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out, key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
                eos.close();
                assertTrue(eos.isDone());
            }
            final byte[] ct = out.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptOutputAlignedByte() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[2*params.getPlaintextSegmentLen()];

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
            for (int offset = 0; offset < pt.length; offset++) {
                eos.write(pt[offset]);
            }
            eos.close();
            assertTrue(eos.isDone());
        }
        final byte[] ct = out.toByteArray();
        final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
        assertArrayEquals(pt, decrypted);
    }

    @Test
    public void encryptOutputUnalignedByte() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[2*params.getPlaintextSegmentLen() + 37];

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(out,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
            for (int offset = 0; offset < pt.length; offset++) {
                eos.write(pt[offset]);
            }
            eos.close();
            assertTrue(eos.isDone());
        }
        final byte[] ct = out.toByteArray();
        final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ct);
        assertArrayEquals(pt, decrypted);
    }

    @Test
    public void encryptInputSmokeAligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4 + 3];

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);
            final ByteArrayOutputStream ct = new ByteArrayOutputStream();
            final byte[] buff = new byte[size];
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in, key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                boolean done = false;
                int offset = 0;
                while (!done) {
                    offset = 0;
                    while (offset < buff.length) {
                        int read = eis.read(buff, offset, buff.length - offset);
                        if (read == -1) {
                            done = true;
                            break;
                        }
                        offset += read;
                    }
                    
                    ct.write(buff, 0, offset);
                    offset = 0;
                }
                assertTrue(eis.isDone());

            }
            final byte[] ctArr = ct.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ctArr);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptInputEmpty() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[0];

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);
            final ByteArrayOutputStream ct = new ByteArrayOutputStream();
            final byte[] buff = new byte[size];
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                boolean done = false;
                int offset = 0;
                while (!done) {
                    offset = 0;
                    while (offset < buff.length) {
                        int read = eis.read(buff, offset, buff.length - offset);
                        if (read == -1) {
                            done = true;
                            break;
                        }
                        offset += read;
                    }
                    
                    ct.write(buff, 0, offset);
                    offset = 0;
                }
                assertTrue(eis.isDone());

            }
            final byte[] ctArr = ct.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ctArr);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptInputSmokeUnaligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4];

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);
            final ByteArrayOutputStream ct = new ByteArrayOutputStream();
            final byte[] buff = new byte[size];
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
                boolean done = false;
                int offset = 0;
                while (!done) {
                    offset = 0;
                    while (offset < buff.length) {
                        int read = eis.read(buff, offset, buff.length - offset);
                        if (read == -1) {
                            done = true;
                            break;
                        }
                        offset += read;
                    }
                    
                    ct.write(buff, 0, offset);
                    offset = 0;
                }
                assertTrue(eis.isDone());
            }
            final byte[] ctArr = ct.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ctArr);
            assertArrayEquals(pt, decrypted);
        }
    }

    @Test
    public void encryptInputSmokeAlignedByte() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4];

        final ByteArrayInputStream in = new ByteArrayInputStream(pt);
        final ByteArrayOutputStream ct = new ByteArrayOutputStream();
        try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
            int read = -1;
            while ((read = eis.read()) != -1) {
                ct.write(read);
            }
            final byte[] ctArr = ct.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ctArr);
            assertArrayEquals(pt, decrypted);
            assertTrue(eis.isDone());
        }
    }

    @Test
    public void encryptInputSmokeUnalignedByte() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4 + 3];

        final ByteArrayInputStream in = new ByteArrayInputStream(pt);
        final ByteArrayOutputStream ct = new ByteArrayOutputStream();
        try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in,  key, "AAD".getBytes(StandardCharsets.UTF_8), params, true)) {
            int read = -1;
            while ((read = eis.read()) != -1) {
                ct.write(read);
            }
            final byte[] ctArr = ct.toByteArray();
            final byte[] decrypted = decrypt(floe, key, "AAD".getBytes(StandardCharsets.UTF_8), ctArr);
            assertArrayEquals(pt, decrypted);
            assertTrue(eis.isDone());
        }
    }

    @Test
    public void truncatedOutputDecryptionFails() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen()];
        Arrays.fill(pt, (byte) 1);
        final SequentialEncryptor encryptor = floe.createEncryptor(key, "AAD".getBytes(StandardCharsets.UTF_8));
        final byte[] header = encryptor.getHeader();
        final byte[] ct = encryptor.processSegment(pt);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                FloeDecryptingOutputStream dos = floe.createDecryptor(key, "AAD".getBytes(StandardCharsets.UTF_8), baos, header)) {
            dos.write(ct);
            final byte[] buff = baos.toByteArray();
            assertArrayEquals(pt, buff);
            assertFalse(dos.isDone());
            assertThrows(IOException.class, () -> dos.close());
        } catch (final IOException e) {
            // Expected
        }
    }

    @Test
    public void truncatedPartialOutputDecryptionFails() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen()];
        Arrays.fill(pt, (byte) 1);
        final SequentialEncryptor encryptor = floe.createEncryptor(key, "AAD".getBytes(StandardCharsets.UTF_8));
        final byte[] header = encryptor.getHeader();
        final byte[] ct = encryptor.processSegment(pt);
        final byte[] ct2 = encryptor.processLastSegment(pt);
        final byte[] ct2Truncated = Arrays.copyOf(ct2, ct2.length - 16);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                FloeDecryptingOutputStream dos = floe.createDecryptor(key, "AAD".getBytes(StandardCharsets.UTF_8), baos, header)) {
            dos.write(ct);
            final byte[] buff = baos.toByteArray();
            assertArrayEquals(pt, buff);
            assertFalse(dos.isDone());
            dos.write(ct2Truncated);
            assertFalse(dos.isDone());
            assertThrows(IOException.class, () -> dos.close());
        } catch (final IOException e) {
            // Expected
        }
    }

    @Test
    public void truncatedInputDecryptionFails() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen()];
        Arrays.fill(pt, (byte) 1);
        final SequentialEncryptor encryptor = floe.createEncryptor(key, "AAD".getBytes(StandardCharsets.UTF_8));
        final byte[] header = encryptor.getHeader();
        final byte[] ct = encryptor.processSegment(pt);
        try (FloeDecryptingInputStream dis = floe.createDecryptor(key, "AAD".getBytes(StandardCharsets.UTF_8), new ByteArrayInputStream(ct), header)) {
            final byte[] buff = new byte[params.getPlaintextSegmentLen()];
            final int read = dis.read(buff);
            assertEquals(buff.length, read);
            assertArrayEquals(pt, buff);
            assertFalse(dis.isDone());
            assertThrows(IOException.class, () -> dis.close());
        } catch (final IOException e) {
            // Expected
        }
    }

    @Test
    public void truncatedPartialInputDecryptionFails() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;
        final Floe floe = Floe.getInstance(params);

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen()];
        Arrays.fill(pt, (byte) 1);
        final SequentialEncryptor encryptor = floe.createEncryptor(key, "AAD".getBytes(StandardCharsets.UTF_8));
        final byte[] header = encryptor.getHeader();
        final byte[] ct = encryptor.processSegment(pt);
        final byte[] ct2 = encryptor.processLastSegment(pt);
        final byte[] ct2Truncated = Arrays.copyOf(ct2, ct2.length - 16);
        final byte[] truncatedCt = new byte[ct.length + ct2Truncated.length];
        System.arraycopy(ct, 0, truncatedCt, 0, ct.length);
        System.arraycopy(ct2Truncated, 0, truncatedCt, ct.length, ct2Truncated.length);
        try (FloeDecryptingInputStream dis = floe.createDecryptor(key, "AAD".getBytes(StandardCharsets.UTF_8), new ByteArrayInputStream(truncatedCt), header)) {
            final byte[] buff = new byte[params.getPlaintextSegmentLen()];
            int read = dis.read(buff);
            assertEquals(buff.length, read);
            assertArrayEquals(pt, buff);
            assertFalse(dis.isDone());
            assertThrows(IOException.class, () -> dis.read(buff));
            assertThrows(IOException.class, () -> dis.close());
        } catch (final IOException e) {
            // Expected
        }
    }

    @Test
    public void decryptOutputKat() throws Exception {
        FloeParameterSpec params = Floe.GCM256_IV256_4K;
        SecretKey key = new SecretKeySpec(new byte[params.getAead().getKeyLength()], "FLOE");

        byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);

        String[] kats = loadKatsFromFile("java_GCM256_IV256_4K");
        byte[] ciphertext = Hex.decodeHex(kats[0]);
        byte[] plaintext = Hex.decodeHex(kats[1]);

        
        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(decrypted, key, aad, params)) {
                for (int offset = 0; offset < ciphertext.length; offset += size) {
                    int toWrite = Math.min(size, ciphertext.length - offset);
                    dos.write(ciphertext, offset, toWrite);
                }
            }
            assertArrayEquals(plaintext, decrypted.toByteArray());
        }
    }

    @Test
    public void decryptOutputKatByte() throws Exception {
        FloeParameterSpec params = Floe.GCM256_IV256_4K;
        SecretKey key = new SecretKeySpec(new byte[params.getAead().getKeyLength()], "FLOE");

        byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);

        String[] kats = loadKatsFromFile("java_GCM256_IV256_4K");
        byte[] ciphertext = Hex.decodeHex(kats[0]);
        byte[] plaintext = Hex.decodeHex(kats[1]);

        
        final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(decrypted, key, aad, params)) {
            for (byte b : ciphertext) {
                dos.write(b & 0xFF);
            }
            dos.close();
            assertTrue(dos.isDone());
        }
        assertArrayEquals(plaintext, decrypted.toByteArray());
    }

    @Test
    public void outputCycleAligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(out, key, pt, params);
                 FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(dos, key, pt, params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
            }
            assertArrayEquals(pt, out.toByteArray());
        }
    }

    @Test
    public void outputCycleUnaligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4 + 47];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(out, key, pt, params);
                 FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(dos, key, pt, params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
            }
            assertArrayEquals(pt, out.toByteArray());
        }
    }
   
    @Test
    public void outputCycleSmall() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[8];

        for (int size : CHUNK_SIZES) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(out, key, pt, params);
                 FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(dos, key, pt, params, true)) {
                for (int offset = 0; offset < pt.length; offset += size) {
                    int toWrite = Math.min(size, pt.length - offset);
                    eos.write(pt, offset, toWrite);
                }
            }
            assertArrayEquals(pt, out.toByteArray());
        }
    }

    @Test
    public void outputCycleEmpty() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[0];

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (FloeDecryptingOutputStream dos = new FloeDecryptingOutputStream(out, key, pt, params);
                FloeEncryptingOutputStream eos = new FloeEncryptingOutputStream(dos, key, pt, params, true)) {
            // Do nothing
        }
        assertArrayEquals(pt, out.toByteArray());
    }

    @Test
    public void inputCycleAligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4];
        final byte[] aad = "AAD".getBytes(StandardCharsets.UTF_8);

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);            
            final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in, key, aad, params, true);
                 FloeDecryptingInputStream dis = new FloeDecryptingInputStream(eis, key, aad, params)) {
                    final byte[] buff = new byte[size];

                    boolean done = false;
                    int offset = 0;
                    while (!done) {
                        offset = 0;
                        while (offset < buff.length) {
                            int read = dis.read(buff, offset, buff.length - offset);
                            if (read == -1) {
                                done = true;
                                break;
                            }
                            offset += read;
                        }
                        
                        decrypted.write(buff, 0, offset);
                        offset = 0;
                    }
            }
            assertArrayEquals(pt, decrypted.toByteArray());
        }
    }

    @Test
    public void inputCycleUnaligned() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[params.getPlaintextSegmentLen() * 4 + 47];
        final byte[] aad = "AAD".getBytes(StandardCharsets.UTF_8);

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);            
            final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in, key, aad, params, true);
                 FloeDecryptingInputStream dis = new FloeDecryptingInputStream(eis, key, aad, params)) {
                    final byte[] buff = new byte[size];

                    boolean done = false;
                    int offset = 0;
                    while (!done) {
                        offset = 0;
                        while (offset < buff.length) {
                            int read = dis.read(buff, offset, buff.length - offset);
                            if (read == -1) {
                                done = true;
                                break;
                            }
                            offset += read;
                        }
                        
                        decrypted.write(buff, 0, offset);
                        offset = 0;
                    }
            }
            assertArrayEquals(pt, decrypted.toByteArray());
        }
    }
   
    @Test
    public void inputCycleSmall() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[8];
        final byte[] aad = "AAD".getBytes(StandardCharsets.UTF_8);

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);            
            final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in, key, aad, params, true);
                 FloeDecryptingInputStream dis = new FloeDecryptingInputStream(eis, key, aad, params)) {
                    final byte[] buff = new byte[size];

                    boolean done = false;
                    int offset = 0;
                    while (!done) {
                        offset = 0;
                        while (offset < buff.length) {
                            int read = dis.read(buff, offset, buff.length - offset);
                            if (read == -1) {
                                done = true;
                                break;
                            }
                            offset += read;
                        }
                        
                        decrypted.write(buff, 0, offset);
                        offset = 0;
                    }
            }
            assertArrayEquals(pt, decrypted.toByteArray());
        }
    }

    @Test
    public void inputCycleEmpty() throws Exception {
        final FloeParameterSpec params = Floe.GCM256_IV256_4K;

        final SecretKey key = new SecretKeySpec(new byte[32], "AES");

        final byte[] pt = new byte[0];
        final byte[] aad = "AAD".getBytes(StandardCharsets.UTF_8);

        for (int size : CHUNK_SIZES) {
            final ByteArrayInputStream in = new ByteArrayInputStream(pt);            
            final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (FloeEncryptingInputStream eis = new FloeEncryptingInputStream(in, key, aad, params, true);
                 FloeDecryptingInputStream dis = new FloeDecryptingInputStream(eis, key, aad, params)) {
                    final byte[] buff = new byte[size];

                    boolean done = false;
                    int offset = 0;
                    while (!done) {
                        offset = 0;
                        while (offset < buff.length) {
                            int read = dis.read(buff, offset, buff.length - offset);
                            if (read == -1) {
                                done = true;
                                break;
                            }
                            offset += read;
                        }
                        
                        decrypted.write(buff, 0, offset);
                        offset = 0;
                    }
            }
            assertArrayEquals(pt, decrypted.toByteArray());
        }
    }
    private byte[] decrypt(Floe floe, SecretKey key, byte[] aad, byte[] ciphertext) throws Exception {
        SequentialDecryptor decryptor = floe.createDecryptor(key, aad, ciphertext);
        FloeParameterSpec p = decryptor.getParameterSpec();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
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
        return baos.toByteArray();
    }
}
