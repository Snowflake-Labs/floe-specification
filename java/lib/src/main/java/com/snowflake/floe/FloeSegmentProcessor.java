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
import java.util.Arrays;

public interface FloeSegmentProcessor extends FloeInstance{
    default void processSegment(ByteBuffer input, ByteBuffer output) {
        int result = processSegment(input.array(), input.arrayOffset() + input.position(), output.array(), output.arrayOffset());
        input.position(input.position() + inputSegmentSize());
        output.position(output.position() + outputSegmentSize());
        if (result != outputSegmentSize()) {
            throw new IllegalStateException("Unexpected output length: " + result);
        }
    }
    default byte[] processSegment(byte[] segment) {
        byte[] output = new byte[outputSegmentSize()];
        processSegment(segment, 0, output, 0);
        return output;
    }
    int processSegment(byte[] segment, int inputOffset, byte[] output, int outputOffset);

    default void processLastSegment(ByteBuffer input, ByteBuffer output) {
        int result = processLastSegment(input.array(), input.arrayOffset() + input.position(), input.remaining(), output.array(), output.arrayOffset());
        input.position(input.position() + input.remaining());
        output.position(output.position() + result);
    }
    default byte[] processLastSegment(byte[] segment) {
        byte[] output = new byte[outputSegmentSize()];
        int length = processLastSegment(segment, 0, segment.length, output, 0);
        if (length == output.length) {
            return output;
        } else {
            return Arrays.copyOf(output, length);
        }
    }
    int processLastSegment(byte[] segment, int inputOffset, int inputLength, byte[] output, int outputOffset);
    boolean isDone();
}
