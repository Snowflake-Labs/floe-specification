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

public class FloeEncryptingInputStream extends InputStream implements FloeStream {
    private final SequentialEncryptor floe;
    private final InputStream in;
    private final ByteBuffer outBuffer;
    private final ByteBuffer inBuffer;
    private byte[] header;
    private int headerOffset = 0;
    private boolean closed = false;
    private boolean done = false;

    FloeEncryptingInputStream(InputStream in, SecretKey key, byte[] aad,  FloeParameterSpec params, boolean needHeader) {
        this.in = in;
        this.floe = Floe.getInstance(params).createEncryptor(key, aad);
        this.outBuffer = ByteBuffer.allocate(floe.outputSegmentSize());
        this.outBuffer.limit(0);
        this.inBuffer = ByteBuffer.allocate(floe.inputSegmentSize());
        if (needHeader) {
            header = floe.getHeader();
        }
    }

    public byte[] getHeader() {
        return floe.getHeader();
    }

    @Override
    public int read() throws IOException {
        assertNotClosed();
        if (header != null && headerOffset < header.length) {
            return header[headerOffset++] & 0xFF;
        }
        while (!done && !outBuffer.hasRemaining()) {
            fillBuffer();
        }

        if (outBuffer.hasRemaining()) {
            return outBuffer.get() & 0xFF;
        } else {
            return -1;
        }
    }

    @Override
    public int read(final byte[] out, int offset, int length) throws IOException {
        assertNotClosed();
        if (header != null && headerOffset < header.length) {
            int toCopy = Math.min(length, header.length - headerOffset);
            System.arraycopy(header, headerOffset, out, offset, toCopy);
            headerOffset += toCopy;
            return toCopy;
        }
        if (!done && !outBuffer.hasRemaining()) {
            fillBuffer();
        }
        if (outBuffer.hasRemaining()) {
            int toCopy = Math.min(length, outBuffer.remaining());
            outBuffer.get(out, offset, toCopy);
            return toCopy;
        } else {
            return done ? -1 : 0;
        }
    }

    private void fillBuffer() throws IOException {
        if (done) {
            return;
        }
        if (inBuffer.hasRemaining()) {
            int read = in.read(inBuffer.array(), inBuffer.position(), inBuffer.remaining());
            if (read == -1) {
                done = true;
            } else {
                inBuffer.position(inBuffer.position() + read);
            }
        }
        if (done) {
            inBuffer.flip();
            outBuffer.clear();
            floe.processLastSegment(inBuffer, outBuffer);
            inBuffer.clear();
            outBuffer.flip();
        } else if (!inBuffer.hasRemaining()) {
            inBuffer.flip();
            outBuffer.clear();
            floe.processSegment(inBuffer, outBuffer);
            outBuffer.flip();
            inBuffer.clear();
        }
    }

    private void assertNotClosed() throws IOException {
        if (closed) {
            throw new IOException("Stream is closed");
        }
    }

    @Override
    public FloeParameterSpec getParameterSpec() {
        return floe.getParameterSpec();
    }

    @Override
    public int inputSegmentSize() {
        return floe.inputSegmentSize();
    }

    @Override
    public int outputSegmentSize() {
        return floe.outputSegmentSize();
    }

    @Override
    public boolean isDone() {
        return done;
    }
}
