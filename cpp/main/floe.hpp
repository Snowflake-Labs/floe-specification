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

#pragma once

#include <cassert>
#include <cstddef>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "absl/types/span.h"
#include "platform.hpp"

namespace sf {

enum class FloeResult {
  Success,
  Unexpected,
  BadHeader,
  BadTag,
  Truncated,
  Closed,
  DataOverflow,
  SegmentOverflow,
  MalformedSegment,
  NotInitialized,
  AlreadyInitialized,
  InvalidInput
};

const char* floeErrorMessage(FloeResult errorCode);

class FloeCryptor;
class FloeEncryptor;
class FloeDecryptor;
class FloeKey;
class AeadCryptor;
class FloeKeyPrivateState;
class FloePurpose;

enum class FloeAead { UNDEFINED, AES_256_GCM };
enum class FloeHash { UNDEFINED, SHA_384 };

// Defines the non-cryptographic algorithm parameters that define FLOE's behavior
// Immutable and threadsafe
class FloeParameterSpec {
 public:
  // FLOE with AES-GCM-256, a 256-bit FLOE IV, and 4 kilobyte encrypted segments
  static FloeParameterSpec GCM256_IV256_4K() noexcept;
  // FLOE with AES-GCM-256, a 256-bit FLOE IV, and 1 megabyte encrypted segments
  static FloeParameterSpec GCM256_IV256_1M() noexcept;

  // This is the constructor everyone should use
  FloeParameterSpec(FloeAead aead, FloeHash hash, ub4 segmentLength);

  // Returns an invalid specification which is useful for default constructors
  FloeParameterSpec();

  // Copy constructor
  FloeParameterSpec(const FloeParameterSpec& other);

  // For testing only
  FloeParameterSpec(FloeAead aead, FloeHash hash, ub4 segmentLength, ub8 overrideMask);

  // Copy assignment
  FloeParameterSpec& operator=(const FloeParameterSpec& other);

  [[nodiscard]]
  FloeAead getAead() const noexcept {
    return m_aead;
  }

  [[nodiscard]]
  FloeHash getHash() const noexcept {
    return m_hash;
  }

  // The length in bytes of an encrypted segment.
  // Includes the ciphertext, length header, AEAD IV, and AEAD Tag.
  [[nodiscard]]
  ub4 getEncryptedSegmentLength() const noexcept {
    return m_encryptedSegmentLength;
  }

  // The FLOE IV length in bytes used in the FLOE header.
  [[nodiscard]]
  ub4 getIvLength() const noexcept {
    return m_ivLength;
  }

  // The length of the FLOE header in bytes.
  // Includes the encoded parameters, FLOE IV, and header tag.
  [[nodiscard]]
  size_t getHeaderLength() const noexcept {
    return 10 + m_ivLength + 32;
  }

  // The length in bytes of the plaintext stored in one segment
  [[nodiscard]]
  size_t getPlaintextSegmentLength() const noexcept;

  // Bit mask which defines how often segment keys should be rotated.
  [[nodiscard]]
  ub8 getRotationMask() const noexcept;

  // Encoded version of the parameters which are included in the FLOE header.
  [[nodiscard]]
  const std::vector<ub1>* getEncoded() const noexcept;

  // Does this object represent a valid combination of parameters.
  [[nodiscard]]
  bool isValid() const noexcept;

 private:
  friend FloeCryptor;
  friend FloeEncryptor;
  friend FloeDecryptor;
  friend FloeKey;

  [[nodiscard]]
  std::vector<ub1> encodeHeader() const noexcept;

  FloeAead m_aead;
  FloeHash m_hash;
  ub4 m_encryptedSegmentLength;
  ub4 m_ivLength;
  bool m_hasOverrideMask;
  ub8 m_overrideMask;
  std::vector<ub1> m_encoded;
  std::once_flag m_encodedFlag;
};

// Generic holder for a FLOE Key.
// May be backed by different "holders" of the cryptographic materials.
// FLOE keys also include a FloeParameterSpec because it is generally incorrect to use the same key
// with multiple algorithms and parameters. (It is explicitly okay to use the same key with
// different segment lengths.) Immutable and threadsafe
class FloeKey {
 public:
  FloeKey(const absl::Span<const ub1>& key, const FloeParameterSpec& params) noexcept;

  // Move Constructor
  FloeKey(FloeKey&& other) = delete;
  // Copy Constructor
  FloeKey(FloeKey& other) = delete;
  
  ~FloeKey() noexcept;
  
  [[nodiscard]]
  absl::Span<const ub1> getKey() const noexcept;
  [[nodiscard]]
  FloeParameterSpec getParameterSpec() const noexcept;
  [[nodiscard]]
  bool isValid() const noexcept;

 private:
  friend FloeCryptor;
  friend FloeEncryptor;
  friend FloeDecryptor;

  //  [[nodiscard]]
  //  FloeKey* derive(const std::vector<ub1>& iv, const std::vector<ub1>& aad, const
  //  absl::Span<const ub1>& purpose,
  //                  size_t purposeLength, size_t len) const noexcept;
  [[nodiscard]]
  std::unique_ptr<FloeKey> derive(const std::vector<ub1>& iv, const std::vector<ub1>& aad,
                                  const FloePurpose& purpose, size_t len) const noexcept;

  std::unique_ptr<FloeKeyPrivateState> m_state;
};

// Base class for both encrypt and decrypt FLOE logic.
// By both exposing compatible APIs, a developer can write code does both encrypt or decrypt with
// only minimal work. These objects are *not* thread-safe but may be used from multiple threads,
// provided that calls are protected by mutexes.
class FloeCryptor {
 public:
  // No copy or move constructors
  FloeCryptor(const FloeCryptor&) = delete;
  FloeCryptor(const FloeCryptor&&) = delete;

  [[nodiscard]]
  FloeParameterSpec getParameterSpec() const noexcept {
    return m_params;
  }

  // The length in bytes of data expected as input to processSegment and maximum accepted by
  // processLastSegment.
  [[nodiscard]] virtual size_t getInputSize() const noexcept = 0;
  // The length in bytes of data output by processSegment.
  [[nodiscard]] virtual size_t getOutputSize() const noexcept = 0;

  // Process (encrypt/decrypt) a non-final segment.
  // See FloeEncryptor and FloeDecryptor for specific behavior.
  [[nodiscard]]
  virtual FloeResult processSegment(const absl::Span<const ub1>& input,
                                    absl::Span<ub1>& output) noexcept = 0;
  // Process (encrypt/decrypt) a non-final segment.
  // See FloeEncryptor and FloeDecryptor for specific behavior.
  [[nodiscard]]
  virtual FloeResult processLastSegment(const absl::Span<const ub1>& input,
                                        absl::Span<ub1>& output) noexcept = 0;
  // What is the output length in bytes of processLastSegment for an input of length
  // lastSegmentSize.
  [[nodiscard]]
  virtual size_t sizeOfLastOutput(size_t lastSegmentSize) const noexcept = 0;

  // Declare the FLOE operation as complete and return a summary success/failure code.
  [[nodiscard]]
  FloeResult finish() const noexcept {
    return isClosed() ? FloeResult::Success : FloeResult::Truncated;
  }

  // Has the FLOE operation completed
  [[nodiscard]]
  bool isClosed() const noexcept {
    return m_closed;
  }

  virtual ~FloeCryptor() noexcept;

 private:
  [[nodiscard]]
  std::unique_ptr<FloeKey> deriveSegmentKey() const noexcept;
  std::vector<ub1> m_floeIv;
  std::vector<ub1> m_aad;
  ub8 m_lastMaskedCounter = UB8_MAX;

 protected:
  FloeCryptor();  // = default;

  // Takes ownership of the key
  void cryptorInitialize(const std::vector<ub1>& iv, const std::vector<ub1>& aad,
                         std::unique_ptr<FloeKey> key) noexcept;

  void useCurrentKey() noexcept;

  void buildSegmentAad(bool last, absl::Span<ub1>& segmentAad) const noexcept;
  FloeParameterSpec m_params;

  ub8 m_counter = 0;
  bool m_closed = false;

  std::unique_ptr<FloeKey> m_messageKey;
  std::unique_ptr<AeadCryptor> m_aeadCryptor;
};

// Class which encrypts data using FLOE.
// See thread safety notes on FloeCryptor.
class FloeEncryptor : public FloeCryptor {
 public:
  // Factory for this object.
  // No references are kept to passed in data.
  static std::pair<FloeResult, std::unique_ptr<FloeEncryptor>> create(
      const FloeKey&, const absl::Span<const ub1>& aad) noexcept;
  // No copy or move constructors
  FloeEncryptor(const FloeEncryptor&) = delete;
  FloeEncryptor(const FloeEncryptor&&) = delete;
  ~FloeEncryptor() override = default;
  // Retrieve the FLOE header.
  // As this *must* be passed to the decryption logic, it should either be:
  //  1. Prepended to the ciphertext
  //  2. Stored as metadata on the file containing the ciphertext
  [[nodiscard]]
  absl::Span<const ub1> getHeader() const noexcept;
  [[nodiscard]]
  size_t getInputSize() const noexcept override;
  [[nodiscard]]
  size_t getOutputSize() const noexcept override;
  // Encrypts a non-final segment. The length of `input` *must* be `getInputSize()` bytes
  // (the size of a Plaintext Segment). The output will be `getOutputSize()` bytes
  // (the size of an Encrypted Segment).
  [[nodiscard]]
  FloeResult processSegment(const absl::Span<const ub1>& input,
                            absl::Span<ub1>& output) noexcept override;
  // Encrypts the final segment. The length of `input` must be no more than `getInputSize()` bytes
  // (the size of a Plaintext Segment). The output size is defined as the result of
  // `sizeOfLastOutput()`. If this method returns successfully then it closes the FloeCryptor.
  [[nodiscard]]
  FloeResult processLastSegment(const absl::Span<const ub1>& input,
                                absl::Span<ub1>& output) noexcept override;
  [[nodiscard]]
  size_t sizeOfLastOutput(size_t lastSegmentSize) const noexcept override;

 private:
  FloeResult initialize(const FloeKey&, const absl::Span<const ub1>& aad) noexcept;
  FloeEncryptor() = default;
  std::vector<ub1> m_header;
};

// Class which decrypts data using FLOE.
// See thread safety notes on FloeCryptor.
class FloeDecryptor : public FloeCryptor {
 public:
  // Factory for this object.
  // No references are kept to passed in data.
  static std::pair<FloeResult, std::unique_ptr<FloeDecryptor>> create(
      const FloeKey& key, const absl::Span<const ub1>& aad,
      const absl::Span<const ub1>& header) noexcept;
  // No copy or move constructors
  FloeDecryptor(const FloeDecryptor&) = delete;
  FloeDecryptor(const FloeDecryptor&&) = delete;
  [[nodiscard]]
  size_t getInputSize() const noexcept override;
  [[nodiscard]]
  size_t getOutputSize() const noexcept override;
  // Decrypts a single non-final segment.
  // The input *must* be of length `getInputLength()` (which is the length of an Encrypted Segment).
  // This method inspects the length header of each segment and if the input appears to be a final
  // segment it transparently calls `processLastSegment()` internally and acts identically to it.
  [[nodiscard]]
  FloeResult processSegment(const absl::Span<const ub1>& input,
                            absl::Span<ub1>& output) noexcept override;
  // Decrypts the final segment. The length of `input` must be no more than `getInputSize()` bytes
  // (the size of an Encrypted Segment) and must be at least 4 + AEAD_IV_LENGTH + AEAD_TAG_LENGTH.
  // (For all currently defined AEADs, this gives a minimum length of 32 bytes.)
  // The output size is defined as the result of `sizeOfLastOutput()`.
  // If this method returns successfully then it closes the FloeCryptor.
  [[nodiscard]]
  FloeResult processLastSegment(const absl::Span<const ub1>& input,
                                absl::Span<ub1>& output) noexcept override;
  [[nodiscard]]
  size_t sizeOfLastOutput(size_t lastSegmentSize) const noexcept override;

 private:
  FloeDecryptor() = default;
  FloeResult initialize(const FloeKey& key, const absl::Span<const ub1>& aad,
                        const absl::Span<const ub1>& header) noexcept;
};
}  // namespace sf
