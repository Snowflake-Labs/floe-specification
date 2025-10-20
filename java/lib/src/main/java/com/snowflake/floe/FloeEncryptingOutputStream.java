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

public class FloeEncryptingOutputStream extends OutputStream implements FloeStream {
    private final SequentialEncryptor floe;
    private final OutputStream out;
    private final ByteBuffer ptBuff;
    private final ByteBuffer ctBuff;
    private boolean needHeader;
    private boolean closed = false;

    FloeEncryptingOutputStream(OutputStream out, SecretKey key, byte[] aad, FloeParameterSpec params, boolean needHeader) {
        this.out = out;
        this.floe = Floe.getInstance(params).createEncryptor(key, aad);
        this.ptBuff = ByteBuffer.allocate(params.getPlaintextSegmentLen());
        this.ctBuff = ByteBuffer.allocate(params.getEncryptedSegmentLength());
        this.needHeader = needHeader;
    }

    @Override
    public void write(int val) throws IOException {
        assertNotClosed();
        if (needHeader) {
            out.write(floe.getHeader());
            needHeader = false;
        }
        ptBuff.put((byte) val);
        maybeFlush();
    }

    @Override
    public void write(byte[] input, int offset, int length) throws IOException {
        assertNotClosed();
        if (needHeader) {
            out.write(floe.getHeader());
            needHeader = false;
        }
        while (length > 0) {
            final int toCopy = Math.min(length, ptBuff.remaining());
            ptBuff.put(input, offset, toCopy);
            offset += toCopy;
            length -= toCopy;
            maybeFlush();
        }
    }
    private void maybeFlush() throws IOException {
        if (ptBuff.hasRemaining()) {
            return;
        }
        ptBuff.flip();
        ctBuff.clear();
        floe.processSegment(ptBuff, ctBuff);
        ptBuff.clear();
        ctBuff.flip();
        out.write(ctBuff.array(), ctBuff.arrayOffset() + ctBuff.position(), ctBuff.remaining());
    }

    @Override
    public void close() throws  IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (needHeader) {
            out.write(floe.getHeader());
        }
        ptBuff.flip();
        ctBuff.clear();
        floe.processLastSegment(ptBuff, ctBuff);
        ptBuff.clear();
        ctBuff.flip();
        out.write(ctBuff.array(), ctBuff.arrayOffset() + ctBuff.position(), ctBuff.remaining());
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
        return closed;
    }

    @Override
    public byte[] getHeader() {
        return floe.getHeader();
    }
}
