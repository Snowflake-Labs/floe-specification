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

import java.nio.ByteBuffer;
import java.util.Optional;

public class FloeParameterSpec {
    private final FloeAead aead;
    private final FloeHash hash;
    private final int segmentLength;
    private final int ivLength;
    private final ByteBuffer encoded;
    // This exists just for testing purposes
    private final Optional<Long> overrideRotationMask;

    FloeParameterSpec(final FloeAead aead, final FloeHash hash, final int segmentLength, final int ivLength) {
        if (ivLength < 32) {
            throw new IllegalArgumentException("ivLength must be at least 32");
        }
        this.aead = aead;
        this.hash = hash;
        this.segmentLength = segmentLength;
        this.ivLength = ivLength;
        encoded = ByteBuffer.allocate(10);
        encoded.put((byte) getAead().getId());
        encoded.put((byte) getHash().getId());
        encoded.putInt(getEncryptedSegmentLength());
        encoded.putInt(getIvLength());
        encoded.flip();
        overrideRotationMask = Optional.empty();
    }

    // VisibleForTesting
    FloeParameterSpec(final FloeAead aead, final FloeHash hash, final int segmentLength, final int ivLength, final long overrideRotationMask) {
        if (ivLength < 32) {
            throw new IllegalArgumentException("ivLength must be at least 32");
        }
        this.aead = aead;
        this.hash = hash;
        this.segmentLength = segmentLength;
        this.ivLength = ivLength;
        encoded = ByteBuffer.allocate(10);
        encoded.put((byte) getAead().getId());
        encoded.put((byte) getHash().getId());
        encoded.putInt(getEncryptedSegmentLength());
        encoded.putInt(getIvLength());
        encoded.flip();
        this.overrideRotationMask = Optional.of(overrideRotationMask);
    }

    public FloeAead getAead() {
        return aead;
    }

    public FloeHash getHash() {
        return hash;
    }

    public int getEncryptedSegmentLength() {
        return segmentLength;
    }

    public int getIvLength() {
        return ivLength;
    }

    public int getPlaintextSegmentLen() {
        return segmentLength - aead.getNonceLength() - aead.getTagLength() - 4;
    }

    public int getHeaderLen() {
        return encoded.remaining() + ivLength + 32;
    }

    ByteBuffer getEncoded() {
        return encoded.asReadOnlyBuffer();
    }

    // VisibleForTesting
    long getOverrideRotationMask() {
        return overrideRotationMask.orElse(aead.getRotationMask());
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((aead == null) ? 0 : aead.hashCode());
        result = prime * result + ((hash == null) ? 0 : hash.hashCode());
        result = prime * result + segmentLength;
        result = prime * result + ivLength;
        return result;
    }

    public static FloeParameterSpec fromEncoded(ByteBuffer encoded) {
        FloeAead aead = FloeAead.fromId(encoded.get());
        FloeHash hash = FloeHash.fromId(encoded.get());
        int segmentLength = encoded.getInt();
        int ivLength = encoded.getInt();
        return new FloeParameterSpec(aead, hash, segmentLength, ivLength);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        FloeParameterSpec other = (FloeParameterSpec) obj;
        if (aead != other.aead)
            return false;
        if (hash != other.hash)
            return false;
        if (segmentLength != other.segmentLength)
            return false;
        if (ivLength != other.ivLength)
            return false;
        return true;
    }
}
