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
import java.io.InputStream;
import java.nio.ByteBuffer;

import javax.crypto.SecretKey;

public class FloeDecryptingInputStream extends InputStream implements FloeStream {
    private final SecretKey key;
    private final byte[] aad;
    private final FloeParameterSpec params;
    private final InputStream in;
    private final ByteBuffer headerBuffer;
    private final ByteBuffer ctBuffer;
    private final ByteBuffer ptBuffer;
    private Decryptor floe;
    private boolean closed = false;
    private boolean done;
    private boolean truncated;
    private int lastSegmentLength;
    
    FloeDecryptingInputStream(InputStream in, SecretKey key, byte[] aad, FloeParameterSpec params) {
        this.in = in;
        this.key = key;
        this.params = params;
        this.aad = aad != null ? aad.clone() : null;
        this.headerBuffer = ByteBuffer.allocate(params.getHeaderLen());
        this.ctBuffer = ByteBuffer.allocate(params.getEncryptedSegmentLength());
        this.ptBuffer = ByteBuffer.allocate(params.getPlaintextSegmentLen());
        ptBuffer.limit(0);
    }

    FloeDecryptingInputStream(InputStream in, SecretKey key, byte[] aad, FloeParameterSpec params, final byte[] header) {
        this.in = in;
        this.key = key;
        this.params = params;
        this.aad = aad != null ? aad.clone() : null;
        this.headerBuffer = null;
        this.ctBuffer = ByteBuffer.allocate(params.getEncryptedSegmentLength());
        this.ptBuffer = ByteBuffer.allocate(params.getPlaintextSegmentLen());
        this.floe = Floe.getInstance(params).createDecryptor(key, aad, header);
        ptBuffer.limit(0);
    }

    @Override
    public int read() throws IOException {
        assertOpen();
        while (floe == null) {
            if (!readHeader()) {
                return -1;
            }
        }
        while (!ptBuffer.hasRemaining() && !done) {
            fillBuffer();
        }
        if (done && truncated) {
            throw new IOException("Ciphertext is truncated");
        }
        if (ptBuffer.hasRemaining()) {
            return ptBuffer.get() & 0xFF;
        } else {
            return -1;
        }
    }

    /** Returns true IFF we have not reached EOF */
    private boolean readHeader() throws IOException {
        int read = in.read(headerBuffer.array(), headerBuffer.position(), headerBuffer.remaining());
        if (read == -1) {
            done = true;
            return false;
        }
        headerBuffer.position(headerBuffer.position() + read);
        if (!headerBuffer.hasRemaining()) {
            headerBuffer.flip();
            floe = Floe.getInstance(params).createDecryptor(key, aad, headerBuffer.array());
        }
        return true;
    }

    private void fillBuffer() throws IOException {
        if (done) {
            return;
        }
        if (ctBuffer.position() < 4) {
            int read = in.read(ctBuffer.array(), ctBuffer.position(), 4 - ctBuffer.position());
            if (read == -1) {
                done = true;
                truncated = true;
                return;
            }
            ctBuffer.position(ctBuffer.position() + read);
            if (ctBuffer.position() < 4) {
                return;
            }
            ctBuffer.flip();
            lastSegmentLength = ctBuffer.getInt();
            if (lastSegmentLength == -1) {
                ctBuffer.limit(ctBuffer.capacity());
            } else {
                ctBuffer.limit(lastSegmentLength);
            }
        }

        if (ctBuffer.hasRemaining()) {
            int read = in.read(ctBuffer.array(), ctBuffer.position(), ctBuffer.remaining());
            if (read == -1) {
                done = true;
                truncated = true;
                return;
            }
            ctBuffer.position(ctBuffer.position() + read);
        }

        if (!ctBuffer.hasRemaining()) {
            if (lastSegmentLength == -1) {
                ctBuffer.flip();
                ptBuffer.clear();
                floe.processSegment(ctBuffer, ptBuffer);
                ctBuffer.clear();
                ptBuffer.flip();
            } else {
                ctBuffer.flip();
                ptBuffer.clear();
                floe.processLastSegment(ctBuffer, ptBuffer);
                ptBuffer.flip();
                done = true;
            }
        }
    }

    private void assertOpen() throws IOException {
        if (closed) {
            throw new IOException("Stream is closed");
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        if (!floe.isDone()) {
            throw new IOException("Ciphertext is truncated");
        }
        closed = true;
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
        return done;
    }

    @Override
    public byte[] getHeader() {
        return floe == null ? null : headerBuffer.array().clone();
    }
}
