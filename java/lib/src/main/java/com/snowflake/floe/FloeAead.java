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

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;

public enum FloeAead {
    AES_GCM_256(0, "AES", "AES/GCM/NoPadding", 32, 12, 16, 20, 1L << 40);

    private final int id;
    private final String jceKeyAlg;
    private final String jceName;
    private final int keyLength;
    private final int nonceLength;
    private final int tagLength;
    private final long rotationMask;
    private final long maxSegements;

    FloeAead(int id, String jceKeyAlg, String jceName, int keyLength, int nonceLength, int tagLength, int maskBits, long maxSegments) {
        this.id = id;
        this.jceKeyAlg = jceKeyAlg;
        this.jceName = jceName;
        this.keyLength = keyLength;
        this.nonceLength = nonceLength;
        this.tagLength = tagLength;
        long tmpMask = 1L << maskBits;
        tmpMask--;
        tmpMask = ~tmpMask;
        this.rotationMask = tmpMask;
        this.maxSegements = maxSegments;
    }

    public int getId() {
        return id;
    }

    String getJceName() {
        return jceName;
    }

    String getJceKeyAlg() {
        return jceKeyAlg;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public int getNonceLength() {
        return nonceLength;
    }

    public int getTagLength() {
        return tagLength;
    }

    long getRotationMask() {
        return rotationMask;
    }

    long getMaxSegements() {
        return maxSegements;
    }

    AlgorithmParameterSpec buildSpec(byte[] nonce, int offset) {
        if (jceName.equals("AES/GCM/NoPadding")) {
            return new GCMParameterSpec(tagLength * 8, nonce, offset, nonceLength);
        } else {
            throw new IllegalArgumentException("Unsupported AEAD algorithm: " + jceName);
        }
    }

    static FloeAead fromId(int id) {
        switch (id) {
            case 0:
                return AES_GCM_256;    
            default:
            throw new IllegalArgumentException("Unsupported AEAD algorithm ID: " + id);
        }
    }
}
