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

use std::array::TryFromSliceError;

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
    InvalidInput(String),
    /**
     * The FLOE library encountered an internal error which should not be possible.
     * This is always a result of a bug in FLOE.
     */
    UnexpectedInternalError(Option<Box<dyn std::error::Error>>),
    /**
     * A dependency returned an unexpected error.
     * This is always a result of a bug in FLOE or one of FLOE's dependencies.
     */
    UnexpectedDependencyError(Box<dyn std::error::Error>),
    /**
     * FLOE expected more segments but did not receive them.
     */
    Truncated,
    /**
     * A [crate::FloeCryptor] was used to process data after it was closed.
     */
    Closed,
    /**
     * A [crate::FloeCryptor] was asked to process more segments than is allowed by the [crate::FloeAead].
     */
    SegmentOverflow,
    /**
     * Insufficient output space provided.
     */
    DataOverflow { actual: usize, expected: usize },
    /**
     * The header is invalid without needing to check the tag.
     */
    BadHeader(String),
    /**
     * The tag in the header is incorrect.
     */
    BadHeaderTag,
    /**
     * An encrypted segment is malformed in a way that can be detected without use of cryptography.
     */
    MalformedSegment(String),
    /**
     * An encrypted segment is cryptographically corrupt and cannot be decrypted.
     */
    BadTag,
}

impl Error {
    pub(crate) fn invalid_input<T>(msg: &str) -> Result<T> {
        Err(Error::InvalidInput(msg.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn internal<E: std::error::Error + 'static>(err: E) -> Error {
        Error::UnexpectedInternalError(Some(Box::new(err)))
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedDependencyError(err) => Some(err.as_ref()),
            Self::UnexpectedInternalError(err) => err.as_deref(),
            _ => None,
        }
    }
}

impl From<aead::Error> for Error {
    fn from(err: aead::Error) -> Self {
        Error::UnexpectedDependencyError(Box::new(err))
    }
}

impl From<InvalidLength> for Error {
    fn from(err: InvalidLength) -> Self {
        Error::UnexpectedDependencyError(Box::new(err))
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Self {
        Error::UnexpectedInternalError(Some(Box::new(err)))
    }
    // This error has got to be our own fault
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedInternalError(err) => write!(f, "An unexpected internal error occurred {err:?}"),
            Error::UnexpectedDependencyError(err) => write!(f, "An unexpected dependency error occurred: {err}"),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::Truncated => write!(f, "Input truncated. Final segment not found."),
            Error::Closed => write!(f, "FloeCryptor is closed and cannot take more input."),
            Error::SegmentOverflow => write!(f, "Too many segments"),
            Error::DataOverflow{actual, expected} => write!(f, "Output too small. Needed {expected} but was {actual}"),
            Error::BadHeader(msg) => write!(f, "Bad header: {}", msg),
            Error::MalformedSegment(msg) => write!(f, "Malformed segment: {}", msg),
            Error::BadTag => write!(f, "Bad segment tag"),
            Error::BadHeaderTag => write!(f, "Bad Header: Invalid Tag"),
        }
    }
}
