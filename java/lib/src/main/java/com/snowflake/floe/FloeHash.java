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

public enum FloeHash {
    SHA384(0, "HmacSHA384", 48);

    private final int id;
    private final String jceName;
    private final int length;

    FloeHash(int id, String jceName, int length) {
        this.id = id;
        this.jceName = jceName;
        this.length = length;
    }

    public int getId() {
        return id;
    }

    String getJceName() {
        return jceName;
    }

    int getLength() {
        return length;
    }

    static FloeHash fromId(int id) {
        switch (id) {
            case 0:
                return SHA384;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm ID: " + id);
        }
    }
}
