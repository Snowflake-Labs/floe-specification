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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import javax.crypto.SecretKey;

public class FloeDecryptingOutputStream extends OutputStream implements FloeStream {
    private final SecretKey key;
    private final byte[] aad;
    private final FloeParameterSpec params;
    private final OutputStream out;
    private final ByteBuffer headerBuffer;
    private final ByteBuffer ctBuffer;
    private final ByteBuffer ptBuffer;
    private Decryptor floe;
    private boolean closed = false;
    private boolean inClosing = false;

    FloeDecryptingOutputStream(OutputStream out, SecretKey key, byte[] aad, FloeParameterSpec params) {
        this.out = out;
        this.key = key;
        this.params = params;
        this.aad = aad != null ? aad.clone() : null;
        this.headerBuffer = ByteBuffer.allocate(params.getHeaderLen());
        this.ctBuffer = ByteBuffer.allocate(params.getEncryptedSegmentLength());
        this.ptBuffer = ByteBuffer.allocate(params.getPlaintextSegmentLen());
    }

    FloeDecryptingOutputStream(OutputStream out, SecretKey key, byte[] aad, FloeParameterSpec params, byte[] header) {
        this.out = out;
        this.key = key;
        this.params = params;
        this.aad = aad != null ? aad.clone() : null;
        this.headerBuffer = null;
        this.ctBuffer = ByteBuffer.allocate(params.getEncryptedSegmentLength());
        this.ptBuffer = ByteBuffer.allocate(params.getPlaintextSegmentLen());
        this.floe = Floe.getInstance(params).createDecryptor(key, aad, header);
    }

    @Override
    public void write(int val) throws IOException {
        assertOpen();
        if (floe == null) {
            headerBuffer.put((byte) val);
        } else {
            ctBuffer.put((byte) val);
        }
        maybeFlush();
    }

    @Override
    public void write(byte[] arr, int offset, int len) throws IOException {
        assertOpen();
        if (floe == null) {
            int toCopy = Math.min(len, headerBuffer.remaining());
            headerBuffer.put(arr, offset, toCopy);
            offset += toCopy;
            len -= toCopy;
            maybeFlush();
        }
        while (len > 0) {
            int toCopy = Math.min(len, ctBuffer.remaining());
            ctBuffer.put(arr, offset, toCopy);
            offset += toCopy;
            len -= toCopy;
            maybeFlush();
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        if (!inClosing) {
            ctBuffer.flip();
            inClosing = true;
        }
        try {
            floe.processLastSegment(ctBuffer, ptBuffer);
        } catch (final IllegalArgumentException ex) {
            throw new IOException("Truncated ciphertext", ex);
        }
        closed = true;
        ptBuffer.flip();
        out.write(ptBuffer.array(), ptBuffer.arrayOffset() + ptBuffer.position(), ptBuffer.remaining());
        ptBuffer.clear();
    }

    private void maybeFlush() throws IOException{
        if (floe == null && !headerBuffer.hasRemaining()) {
            floe = Floe.getInstance(params).createDecryptor(key, aad, headerBuffer.array());
        }
        if (!ctBuffer.hasRemaining()) {
            ctBuffer.flip();
            floe.processSegment(ctBuffer, ptBuffer);
            ptBuffer.flip();
            ctBuffer.clear();
            out.write(ptBuffer.array(), ptBuffer.arrayOffset() + ptBuffer.position(), ptBuffer.remaining());
        }
    }

    private void assertOpen() {
        if (closed) {
            throw new IllegalStateException("Stream is closed");
        }
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
    public boolean isDone() {
        return floe != null && floe.isDone();
    }

    @Override
    public byte[] getHeader() {
        return floe == null ? null : headerBuffer.array().clone();
    }
}
