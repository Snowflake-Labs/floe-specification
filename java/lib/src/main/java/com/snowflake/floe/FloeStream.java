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

public interface FloeStream extends FloeInstance{
    /**
     * Returns true if and only if the stream has successfully processed a complete FLOE ciphertext.
     * In the case of encryption, this happens after a final segment has been produced.
     * In the case of decryption, this happens after a final segment has been sucessfully decrypted.
     */
    boolean isDone();

    /**
     * In the case of encryption, this will result in a final segment being produced and the stream being closed.
     * In the case of encryption, this will throw an {@link IOException} if the ciphertext has been truncated.
     * This method will <em>not</em> close the underlying stream.
     */
    void close() throws IOException;

    /**
     * Returns the FLOE header.
     * If this is a decrypting stream and the header is not yet available, returns {@code null} instead.
     */
    byte[] getHeader();
}
