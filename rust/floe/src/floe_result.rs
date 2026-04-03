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

use hmac::digest::InvalidLength;

/// Result type used for all FLOE operations
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
/// Error return type used for all FLOE operations.
pub enum Error {
    /**
     * Calling code provided invalid input to FLOE.
     * This is always a result of buggy calling code.
     */
    InvalidInput,
    /**
     * A dependency returned an unexpected error.
     * This is always a result of a bug in FLOE or one of FLOE's dependencies.
     */
    UnexpectedDependencyError,
    /**
     * FLOE expected more segments but did not receive them.
     */
    Truncated,
    /**
     * A [crate::FloeSequentialCryptor] was used to process data after it was closed.
     */
    Closed,
    /**
     * A [crate::FloeSequentialCryptor] was asked to process more segments than is allowed by the [crate::FloeAead].
     */
    SegmentOverflow,
    /**
     * Insufficient output space provided.
     */
    DataOverflow { actual: usize, expected: usize },
    /**
     * The header is invalid without needing to check the tag.
     */
    BadHeader,
    /**
     * The tag in the header is incorrect.
     */
    BadHeaderTag,
    /**
     * An encrypted segment is malformed in a way that can be detected without use of cryptography.
     */
    MalformedSegment,
    /**
     * An encrypted segment is cryptographically corrupt and cannot be decrypted.
     */
    BadTag,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Error::UnexpectedDependencyError
    }
}

impl From<InvalidLength> for Error {
    fn from(_: InvalidLength) -> Self {
        Error::UnexpectedDependencyError
    }
}

impl From<rand::rngs::SysError> for Error {
    fn from(_: rand::rngs::SysError) -> Self {
        Error::UnexpectedDependencyError
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedDependencyError => {
                write!(f, "An unexpected dependency error occurred")
            }
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::Truncated => write!(f, "Input truncated. Final segment not found."),
            Error::Closed => write!(f, "FloeCryptor is closed and cannot take more input."),
            Error::SegmentOverflow => write!(f, "Too many segments"),
            Error::DataOverflow { actual, expected } => {
                write!(f, "Output too small. Needed {expected} but was {actual}")
            }
            Error::BadHeader => write!(f, "Bad header"),
            Error::MalformedSegment => write!(f, "Malformed segment"),
            Error::BadTag => write!(f, "Bad segment tag"),
            Error::BadHeaderTag => write!(f, "Bad Header: Invalid Tag"),
        }
    }
}
