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

//! Fast Lightweight Online Encryption (FLOE)
//!
//! FLOE is random-access authenticated encryption algorithm that also serves
//! as an online (i.e., streaming) authenticated encryption algorithm.
//! It is described in greater detail both in the primary specification repository
//! at [github.com/Snowflake-Labs/floe-specification](https://www.github.com/Snowflake-Labs/floe-specification)
//! and at [c2sp.org/FLOE](https://c2sp.org/FLOE).
//! 
//! We recommend that most developers use the streaming interfaces as implemented by
//! [FloeSequentialEncryptor] and [FloeSequentialDecryptor] as they are much harder to misuse.
//! More advanced users can directly use [FloeEncryptor] and [FloeDecryptor] if full random-access
//! authenticated encryption is needed.
//! 
//! <div class="warning">The random-access APIs do not directly protect you against truncation attacks
//! or prevent you from incorrectly encrypting the same segment multiple times.</div>

mod constants;
mod floe_result;
mod implementation;
mod interface;
mod ra;
mod types;

pub use floe_result::Error;
pub use floe_result::Result;
pub use implementation::FloeSequentialDecryptor;
pub use implementation::FloeSequentialEncryptor;
pub use interface::FloeSequentialCryptor;
pub use ra::FloeDecryptor;
pub use ra::FloeEncryptor;
pub use types::FloeAead;
pub use types::FloeKdf;
pub use types::FloeKey;
pub use types::FloeParameterSpec;
pub use types::GCM256_IV256_1M;
pub use types::GCM256_IV256_4K;
pub use types::GCM256_IV256_16M;

#[cfg(test)]
mod tests;
