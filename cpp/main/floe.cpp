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

#include "floe.hpp"

#include <cstring>
#include <mutex>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace sf {
namespace {
ub1 getFloeId(FloeAead aead) {
  assert(aead == FloeAead::AES_256_GCM);
  return 0;
}

ub1 getFloeId(FloeHash hash) {
  assert(hash == FloeHash::SHA_384);
  return 0;
}

size_t getHashLength(FloeHash hash) noexcept {
  assert(hash == FloeHash::SHA_384);
  return 48;
}

const char* getOsslHashName(FloeHash hash) noexcept {
  assert(hash == FloeHash::SHA_384);
  return "SHA-384";
}

size_t getKeyLength(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return 32;
}

size_t getNonceLength(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return 12;
}

size_t getTagLength(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return 16;
}

ub8 getRotationMask(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return ~(static_cast<ub8>(0xfffff));
}

size_t getMaxSegments(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return static_cast<size_t>(1) << 40;
}

const EVP_CIPHER* getOsslCipher(FloeAead aead) noexcept {
  assert(aead == FloeAead::AES_256_GCM);
  return EVP_aes_256_gcm();
}

void i2be(ub8 val, absl::Span<ub1> out) {
  out[0] = (val >> 56) & 0xFF;
  out[1] = (val >> 48) & 0xFF;
  out[2] = (val >> 40) & 0xFF;
  out[3] = (val >> 32) & 0xFF;
  out[4] = (val >> 24) & 0xFF;
  out[5] = (val >> 16) & 0xFF;
  out[6] = (val >> 8) & 0xFF;
  out[7] = val & 0xFF;
}

void i2be(ub4 val, absl::Span<ub1> out) {
  out[0] = (val >> 24) & 0xFF;
  out[1] = (val >> 16) & 0xFF;
  out[2] = (val >> 8) & 0xFF;
  out[3] = val & 0xFF;
}

ub4 be2i4(absl::Span<const ub1> arr) {
  ub4 result = 0;
  result |= arr[0] << 24;
  result |= arr[1] << 16;
  result |= arr[2] << 8;
  result |= arr[3];
  return result;
}

const int CIPHER_MODE_ENCRYPT = 1;     // From OpenSSL
const int CIPHER_MODE_DECRYPT = 0;     // From OpenSSL
const int CIPHER_MODE_UNCHANGED = -1;  // From OpenSSL
const size_t SEGMENT_AAD_SIZE = 9;     // 64-bit integer + 1 byte
static_assert(sizeof(ub8) + 1 == SEGMENT_AAD_SIZE);
const size_t SEGMENT_LENGTH_PREFIX = 4;  // 32-bit integer
static_assert(sizeof(ub4) == SEGMENT_LENGTH_PREFIX);
const size_t HEADER_TAG_SIZE = 32;
// TODO: Change this if/when we support more IV lengths
const size_t FLOE_IV_DEFAULT_LENGTH = 32;

void params2Mac(const FloeParameterSpec& params, EVP_MAC** mac, OSSL_PARAM* macParams) noexcept {
  // We assume that if mac is non-null then it is correctly set
  if (*mac != nullptr) {
    EVP_MAC_up_ref(*mac);
  } else {
    *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  }
  const char* digestName = getOsslHashName(params.getHash());
  macParams[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digestName),
                                                  sizeof(digestName) - 1);
  macParams[1] = OSSL_PARAM_construct_end();
}

// Equivalent to `&span[offset]` except that it also works when `offset` is equal to `span.size()`.
ub1* offsetOrEnd(const absl::Span<ub1> span, size_t offset) {
  if (span.size() == offset) {
    return span.end();
  } else {
    return &span[offset];
  }
}
}  // anonymous namespace

class FloePurpose {
 public:
  explicit FloePurpose(const char* str) : m_span{reinterpret_cast<const ub1*>(str), strlen(str)} {}
  explicit FloePurpose(absl::Span<ub1> span) : m_span{span} {}
  absl::Span<const ub1> m_span;
};

// The 8 hashes are saving space for a 64-bit integer
const FloePurpose PURPOSE_DEK("DEK:########");
// Offset of first hash (past end of "DEK:") in PURPOSE_DEK
const size_t PURPOSE_DEK_CTR_OFFSET = 4;
const FloePurpose PURPOSE_HEADER_TAG("HEADER_TAG:");
const FloePurpose PURPOSE_MESSAGE_KEY("MESSAGE_KEY:");

#define FLOE_ERROR_CASE(x) \
  case x:                  \
    return #x

const char* floeErrorMessage(FloeResult errorCode) {
  switch (errorCode) {
    FLOE_ERROR_CASE(FloeResult::Success);
    FLOE_ERROR_CASE(FloeResult::Unexpected);
    FLOE_ERROR_CASE(FloeResult::BadHeader);
    FLOE_ERROR_CASE(FloeResult::BadTag);
    FLOE_ERROR_CASE(FloeResult::Truncated);
    FLOE_ERROR_CASE(FloeResult::Closed);
    FLOE_ERROR_CASE(FloeResult::DataOverflow);
    FLOE_ERROR_CASE(FloeResult::SegmentOverflow);
    FLOE_ERROR_CASE(FloeResult::MalformedSegment);
    FLOE_ERROR_CASE(FloeResult::NotInitialized);
    FLOE_ERROR_CASE(FloeResult::AlreadyInitialized);
    FLOE_ERROR_CASE(FloeResult::InvalidInput);
    default:
      return "Undefined error";
  }
}

#undef FLOE_ERROR_CASE

class AeadCryptor {
 public:
  explicit AeadCryptor(const FloeParameterSpec& spec) noexcept;
  ~AeadCryptor() noexcept { EVP_CIPHER_CTX_free(m_evpCtx); }

  void setKey(const FloeKey& key) noexcept;

  FloeResult encrypt(const absl::Span<const ub1>& in, absl::Span<ub1>& out, size_t* outLen,
                     const absl::Span<const ub1>& aad) noexcept;

  FloeResult decrypt(const absl::Span<const ub1>& in, absl::Span<ub1>& out, size_t* outLen,
                     const absl::Span<const ub1>& aad) noexcept;

 private:
  FloeParameterSpec m_params;
  EVP_CIPHER_CTX* m_evpCtx;
};

// FloeParameterSpec

FloeParameterSpec FloeParameterSpec::GCM256_IV256_4K() noexcept {
  return {FloeAead::AES_256_GCM, FloeHash::SHA_384, 4 * 1024};
}

FloeParameterSpec FloeParameterSpec::GCM256_IV256_1M() noexcept {
  return {FloeAead::AES_256_GCM, FloeHash::SHA_384, 1024 * 1024};
}

FloeParameterSpec::FloeParameterSpec()
    : m_aead{FloeAead::UNDEFINED},
      m_hash{FloeHash::UNDEFINED},
      m_encryptedSegmentLength{0},
      m_ivLength{0},
      m_hasOverrideMask{false},
      m_overrideMask{0} {}

FloeParameterSpec::FloeParameterSpec(const FloeParameterSpec& other)
    : m_aead{other.m_aead},
      m_hash{other.m_hash},
      m_encryptedSegmentLength{other.m_encryptedSegmentLength},
      m_ivLength{other.m_ivLength},
      m_hasOverrideMask{other.m_hasOverrideMask},
      m_overrideMask{other.m_overrideMask} {}

FloeParameterSpec::FloeParameterSpec(FloeAead aead, FloeHash hash, ub4 segmentLength)
    : m_aead{aead},
      m_hash{hash},
      m_encryptedSegmentLength{segmentLength},
      m_ivLength{FLOE_IV_DEFAULT_LENGTH},
      m_hasOverrideMask{false},
      m_overrideMask{0} {}

FloeParameterSpec::FloeParameterSpec(FloeAead aead, FloeHash hash, ub4 segmentLength,
                                     ub8 overrideMask)
    : m_aead{aead},
      m_hash{hash},
      m_encryptedSegmentLength{segmentLength},
      m_ivLength{FLOE_IV_DEFAULT_LENGTH},
      m_hasOverrideMask{true},
      m_overrideMask{overrideMask} {}

FloeParameterSpec& FloeParameterSpec::operator=(const sf::FloeParameterSpec& other) {
  this->m_aead = other.m_aead;
  this->m_hash = other.m_hash;
  this->m_encryptedSegmentLength = other.m_encryptedSegmentLength;
  this->m_ivLength = other.m_ivLength;
  this->m_hasOverrideMask = other.m_hasOverrideMask;
  this->m_overrideMask = other.m_overrideMask;
  if (!this->m_encoded.empty()) {
    m_encoded = encodeHeader();
  }
  return *this;
}

const std::vector<ub1>* FloeParameterSpec::getEncoded() const noexcept {
  auto nonConstFlag = const_cast<std::once_flag*>(&m_encodedFlag);
  auto nonConstEncoded = const_cast<std::vector<ub1>*>(&m_encoded);
  std::call_once(*nonConstFlag,
                 [nonConstEncoded, this]() { *nonConstEncoded = this->encodeHeader(); });
  return &m_encoded;
}

bool FloeParameterSpec::isValid() const noexcept {
  return m_aead != FloeAead::UNDEFINED && m_hash != FloeHash::UNDEFINED &&
         m_encryptedSegmentLength >
             getTagLength(m_aead) + getNonceLength(m_aead) + SEGMENT_LENGTH_PREFIX;
}

class FloeKeyPrivateState {
 public:
  FloeKeyPrivateState() = default;
  ~FloeKeyPrivateState() {
    if (m_mac != nullptr) {
      EVP_MAC_free(m_mac);
    }
    OPENSSL_cleanse(m_key.data(), m_key.size());
  }
  FloeKeyPrivateState(const FloeKeyPrivateState& other)
      : m_key{other.m_key}, m_params{other.m_params}, m_mac{other.m_mac} {
    EVP_MAC_up_ref(other.m_mac);
    m_macParams[0] = other.m_macParams[0];
    m_macParams[1] = OSSL_PARAM_END;
  }
  FloeKeyPrivateState(const absl::Span<const ub1> key, const FloeParameterSpec& params)
      : m_params{params} {
    m_key.insert(m_key.end(), key.begin(), key.end());
    params2Mac(params, &this->m_mac, this->m_macParams);
  }

  std::vector<ub1> m_key;
  FloeParameterSpec m_params;
  EVP_MAC* m_mac = nullptr;

  // Doesn't need to be freed as it's entirely in-place
  OSSL_PARAM m_macParams[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
};

// AeadCryptor

AeadCryptor::AeadCryptor(const FloeParameterSpec& spec) noexcept : m_params{spec} {
  m_evpCtx = EVP_CIPHER_CTX_new();
  // Mode doesn't matter yet so set it arbitrarily
  EVP_CipherInit_ex2(m_evpCtx, getOsslCipher(spec.getAead()), nullptr, nullptr, CIPHER_MODE_ENCRYPT,
                     nullptr);
  EVP_CIPHER_CTX_ctrl(m_evpCtx, EVP_CTRL_AEAD_SET_IVLEN,
                      static_cast<int>(getNonceLength(spec.getAead())), nullptr);
}

void AeadCryptor::setKey(const FloeKey& key) noexcept {
  EVP_CipherInit_ex2(m_evpCtx, nullptr, key.getKey().data(), nullptr, CIPHER_MODE_UNCHANGED,
                     nullptr);
}
FloeResult AeadCryptor::encrypt(const absl::Span<const ub1>& in, absl::Span<ub1>& out,
                                size_t* outLen, const absl::Span<const ub1>& aad) noexcept {
  const size_t nonceLength = getNonceLength(m_params.getAead());
  const size_t tagLength = getTagLength(m_params.getAead());
  size_t neededLength = nonceLength + in.size() + tagLength;
  size_t dataWritten = 0;
  if (neededLength > out.size()) {
    return FloeResult::DataOverflow;
  }
  // TODO: Get IV generated internally once we figure out how
  if (RAND_bytes_ex(nullptr, out.data(), nonceLength, 0) < 0) {
    return FloeResult::Unexpected;
  }
  dataWritten += nonceLength;

  // Set the IV and encryption mode
  if (EVP_CipherInit_ex2(m_evpCtx, nullptr, nullptr, out.data(), CIPHER_MODE_ENCRYPT, nullptr) !=
      1) {
    return FloeResult::Unexpected;
  }

  // Set AAD if present
  int osslOutLen = 0;
  if (!aad.empty()) {
    if (EVP_CipherUpdate(m_evpCtx, nullptr, &osslOutLen, aad.data(),
                         static_cast<int>(aad.size())) != 1) {
      return FloeResult::Unexpected;
    }
  }

  // Encrypt the data
  osslOutLen =
      *outLen - dataWritten;  // Alternates between output buffer size and how much ossl has written
  if (EVP_CipherUpdate(m_evpCtx, offsetOrEnd(out, dataWritten), &osslOutLen, in.data(),
                       static_cast<int>(in.size())) != 1) {
    return FloeResult::Unexpected;
  }
  dataWritten += osslOutLen;
  osslOutLen = *outLen - dataWritten;

  if (EVP_CipherFinal_ex(m_evpCtx, offsetOrEnd(out, dataWritten), &osslOutLen) != 1) {
    return FloeResult::Unexpected;
  }
  dataWritten += osslOutLen;
  osslOutLen = *outLen - dataWritten;
  if (dataWritten != in.size() + nonceLength) {
    // Weird assertion error we need to figure out
    return FloeResult::Unexpected;
  }
  // TODO: Figure out proper return value
  EVP_CIPHER_CTX_ctrl(m_evpCtx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tagLength),
                      offsetOrEnd(out, dataWritten));
  dataWritten += tagLength;
  if (dataWritten != neededLength) {
    return FloeResult::Unexpected;
  }
  *outLen = dataWritten;
  return FloeResult::Success;
}

FloeResult AeadCryptor::decrypt(const absl::Span<const ub1>& in, absl::Span<ub1>& out,
                                size_t* outLen, const absl::Span<const ub1>& aad) noexcept {
  const size_t nonceLength = getNonceLength(m_params.getAead());
  const size_t tagLength = getTagLength(m_params.getAead());
  size_t neededLength = in.size() - nonceLength - tagLength;

  size_t dataWritten = 0;
  if (neededLength > *outLen) {
    return FloeResult::DataOverflow;
  }
  // Read the IV from the input
  if (EVP_CipherInit_ex2(m_evpCtx, nullptr, nullptr, in.data(), CIPHER_MODE_DECRYPT, nullptr) !=
      1) {
    return FloeResult::Unexpected;
  }

  // We know the last tagLength bytes are the tag, so read it
  const void* tagLocation = &in[in.size() - tagLength];
  // TODO: Figure out the return value
  EVP_CIPHER_CTX_ctrl(m_evpCtx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagLength),
                      const_cast<void*>(tagLocation));

  // Set AAD if present
  int osslOutLen = 0;
  if (!aad.empty()) {
    if (EVP_CipherUpdate(m_evpCtx, nullptr, &osslOutLen, aad.data(),
                         static_cast<int>(aad.size())) != 1) {
      return FloeResult::Unexpected;
    }
  }
  osslOutLen = *outLen;
  if (EVP_CipherUpdate(m_evpCtx, out.data(), &osslOutLen, &in[nonceLength],
                       static_cast<int>(neededLength)) != 1) {
    return FloeResult::Unexpected;
  }
  dataWritten += osslOutLen;
  osslOutLen = *outLen - dataWritten;

  // Finalize things and check the tag
  if (EVP_CipherFinal_ex(m_evpCtx, offsetOrEnd(out, dataWritten), &osslOutLen) != 1) {
    return FloeResult::BadTag;
  }
  dataWritten += osslOutLen;
  *outLen = dataWritten;
  return FloeResult::Success;
}

ub8 FloeParameterSpec::getRotationMask() const noexcept {
  return m_hasOverrideMask ? m_overrideMask : ::sf::getRotationMask(m_aead);
}

// FloeKey

FloeKey::FloeKey(const absl::Span<const ub1>& key, const FloeParameterSpec& params) noexcept {
  m_state = std::make_unique<FloeKeyPrivateState>(key, params);
}

FloeKey::~FloeKey() noexcept {
  // NOP
}

absl::Span<const ub1> FloeKey::getKey() const noexcept { return {this->m_state->m_key}; }

FloeParameterSpec FloeKey::getParameterSpec() const noexcept { return this->m_state->m_params; }

bool FloeKey::isValid() const noexcept {
  return getParameterSpec().isValid() &&
    getKey().size() == getKeyLength(getParameterSpec().getAead());
}

std::unique_ptr<FloeKey> FloeKey::derive(const std::vector<ub1>& iv, const std::vector<ub1>& aad,
                                         const FloePurpose& purpose, size_t len) const noexcept {
  assert(len <= getHashLength(m_state->m_params.getHash()));
  EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(m_state->m_mac);

  const ub1 oneByte = 1;
  const auto params = &(m_state->m_params);
  assert(EVP_MAC_init(ctx, m_state->m_key.data(), m_state->m_key.size(), m_state->m_macParams));

  assert(EVP_MAC_update(ctx, params->getEncoded()->data(), params->getEncoded()->size()));
  assert(EVP_MAC_update(ctx, iv.data(), iv.size()));
  assert(EVP_MAC_update(ctx, purpose.m_span.data(), purpose.m_span.size()));
  assert(EVP_MAC_update(ctx, aad.data(), aad.size()));
  assert(EVP_MAC_update(ctx, &oneByte, 1));

  unsigned char buf[48] = {0};  // big enough for now
  assert(sizeof(buf) >= getHashLength(params->getHash()));
  size_t out_len = 0;
  assert(EVP_MAC_final(ctx, buf, &out_len, sizeof(buf)));
  assert(out_len >= len);

  auto result = std::make_unique<FloeKey>(absl::Span<const ub1>(buf, len), *params);
  OPENSSL_cleanse(buf, sizeof(buf));
  EVP_MAC_CTX_free(ctx);
  return result;
}

std::vector<ub1> FloeParameterSpec::encodeHeader() const noexcept {
  std::vector<ub1> result;
  result.reserve(10);
  ub1 rawScratch[] = {0, 0, 0, 0};
  absl::Span<ub1> ub4Scratch(rawScratch);

  result.push_back(getFloeId(m_aead));
  result.push_back(getFloeId(m_hash));

  i2be(m_encryptedSegmentLength, ub4Scratch);
  result.insert(result.end(), ub4Scratch.begin(), ub4Scratch.end());

  i2be(m_ivLength, ub4Scratch);
  result.insert(result.end(), ub4Scratch.begin(), ub4Scratch.end());
  return result;
}

size_t FloeParameterSpec::getPlaintextSegmentLength() const noexcept {
  return m_encryptedSegmentLength - getNonceLength(m_aead) - getTagLength(m_aead) -
         SEGMENT_LENGTH_PREFIX;
}

// FloeCryptor

FloeCryptor::FloeCryptor() = default;
FloeCryptor::~FloeCryptor() noexcept = default;

void FloeCryptor::cryptorInitialize(const std::vector<ub1>& iv, const std::vector<ub1>& aad,
                                    std::unique_ptr<FloeKey> key) noexcept {
  m_floeIv.insert(m_floeIv.end(), iv.begin(), iv.end());
  m_aad.insert(m_aad.end(), aad.begin(), aad.end());
  m_params = key->getParameterSpec();
  m_messageKey = std::move(key);
  m_aeadCryptor = std::make_unique<AeadCryptor>(m_params);
}
void FloeCryptor::buildSegmentAad(bool last, absl::Span<ub1>& segmentAad) const noexcept {
  i2be(m_counter, segmentAad);
  segmentAad[8] = last ? 1 : 0;
}

std::unique_ptr<FloeKey> FloeCryptor::deriveSegmentKey() const noexcept {
  const ub8 mask = m_params.getRotationMask();
  const ub8 maskedSegmentNumber = m_counter & mask;

  std::vector<ub1> mergedPurposeRaw(PURPOSE_DEK.m_span.begin(), PURPOSE_DEK.m_span.end());
  absl::Span<ub1> mergedPurpose(mergedPurposeRaw);
  i2be(maskedSegmentNumber, mergedPurpose.subspan(PURPOSE_DEK_CTR_OFFSET));

  return m_messageKey->derive(m_floeIv, m_aad, FloePurpose(mergedPurpose),
                              getKeyLength(m_params.getAead()));
}

void FloeCryptor::useCurrentKey() noexcept {
  const ub8 mask = m_params.getRotationMask();
  const ub8 maskedSegmentNumber = m_counter & mask;
  if (maskedSegmentNumber != m_lastMaskedCounter) {
    auto sessionKey = deriveSegmentKey();
    m_aeadCryptor->setKey(*sessionKey);
    m_lastMaskedCounter = maskedSegmentNumber;
  }
}

// FloeEncryptor

std::pair<FloeResult, std::unique_ptr<FloeEncryptor>> FloeEncryptor::create(
    const FloeKey& key, const absl::Span<const ub1>& aad) noexcept {
  auto encryptor = std::unique_ptr<FloeEncryptor>(new FloeEncryptor());
  auto result = encryptor->initialize(key, aad);
  if (result != FloeResult::Success) {
    return {result, nullptr};
  } else {
    return {result, std::move(encryptor)};
  }
}

absl::Span<const ub1> FloeEncryptor::getHeader() const noexcept { return m_header; }

FloeResult FloeEncryptor::processSegment(const absl::Span<const ub1>& input,
                                         absl::Span<ub1>& output) noexcept {
  if (m_messageKey == nullptr) {
    return FloeResult::NotInitialized;
  }

  if (isClosed()) {
    return FloeResult::Closed;
  }

  // assert len(plaintext) == ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - SEGMENT_LENGTH_PREFIX
  if (input.size() != getInputSize()) {
    return FloeResult::InvalidInput;
  }
  if (output.size() < getOutputSize()) {
    return FloeResult::DataOverflow;
  }
  // assert State.Counter != 2^32-1 # Prevent overflow
  if (m_counter == getMaxSegments(m_params.getAead()) - 1) {
    return FloeResult::SegmentOverflow;
  }
  // aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, State.Counter)
  useCurrentKey();

  // aead_iv = RND(AEAD_IV_LEN) is implicit in the encryption
  // aead_aad = I2BE(State.Counter, 8) || 0x00
  ub1 rawSegmentAad[SEGMENT_AAD_SIZE];
  absl::Span<ub1> segmentAad(rawSegmentAad);
  buildSegmentAad(false, segmentAad);
  size_t outputSize = getOutputSize() - SEGMENT_LENGTH_PREFIX;
  auto ctSpan = output.subspan(SEGMENT_LENGTH_PREFIX);
  FloeResult result = m_aeadCryptor->encrypt(input, ctSpan, &outputSize, segmentAad);
  if (result != FloeResult::Success) {
    return result;
  }
  i2be(UB4_MAX, output);
  m_counter++;

  return FloeResult::Success;
}

FloeResult FloeEncryptor::processLastSegment(const absl::Span<const ub1>& input,
                                             absl::Span<ub1>& output) noexcept {
  if (m_messageKey == nullptr) {
    return FloeResult::NotInitialized;
  }

  if (isClosed()) {
    return FloeResult::Closed;
  }
  // assert len(plaintext) <= ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - SEGMENT_LENGTH_PREFIX
  if (input.size() > getInputSize()) {
    return FloeResult::DataOverflow;
  }
  size_t outputSize = sizeOfLastOutput(input.size());

  if (output.size() < outputSize) {
    return FloeResult::DataOverflow;
  }

  // aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, State.Counter)
  useCurrentKey();

  // aead_iv = RND(AEAD_IV_LEN) is implicit in the encryption
  // aead_aad = I2BE(State.Counter, 8) || 0x01
  ub1 rawSegmentAad[SEGMENT_AAD_SIZE];
  absl::Span<ub1> segmentAad(rawSegmentAad);
  buildSegmentAad(true, segmentAad);
  size_t ciphertextSize = outputSize - SEGMENT_LENGTH_PREFIX;
  auto ctSpan = output.subspan(SEGMENT_LENGTH_PREFIX);
  FloeResult result = m_aeadCryptor->encrypt(input, ctSpan, &ciphertextSize, segmentAad);
  if (result != FloeResult::Success) {
    return result;
  }
  i2be(static_cast<ub4>(outputSize), output);
  m_closed = true;

  return FloeResult::Success;
}

size_t FloeEncryptor::sizeOfLastOutput(size_t lastSegmentSize) const noexcept {
  return lastSegmentSize + SEGMENT_LENGTH_PREFIX + getTagLength(m_params.getAead()) +
         getNonceLength(m_params.getAead());
}

FloeResult FloeEncryptor::initialize(const FloeKey& key,
                                     const absl::Span<const ub1>& aad) noexcept {
  if (!key.isValid()) {
    return FloeResult::InvalidInput;
  }
  FloeParameterSpec params = key.getParameterSpec();
  std::vector<ub1> iv;
  iv.resize(params.getIvLength());
  if (RAND_bytes(iv.data(), static_cast<int>(params.getIvLength())) != 1) {
    return FloeResult::Unexpected;
  }
  std::vector<ub1> aadVec(aad.begin(), aad.end());

  m_header.reserve(params.getHeaderLength());
  m_header.insert(m_header.end(), params.getEncoded()->begin(), params.getEncoded()->end());
  m_header.insert(m_header.end(), iv.begin(), iv.end());

  // HeaderTag = FLOE_KDF(key, iv, aad, “HEADER_TAG:”)
  auto tagAsKey = key.derive(iv, aadVec, PURPOSE_HEADER_TAG, HEADER_TAG_SIZE);
  auto tag = tagAsKey->getKey();
  m_header.insert(m_header.end(), tag.begin(), tag.end());

  auto messageKey = key.derive(iv, aadVec, PURPOSE_MESSAGE_KEY, getHashLength(params.getHash()));
  cryptorInitialize(iv, aadVec, std::move(messageKey));
  return FloeResult::Success;
}

size_t FloeEncryptor::getInputSize() const noexcept { return m_params.getPlaintextSegmentLength(); }

size_t FloeEncryptor::getOutputSize() const noexcept {
  return m_params.getEncryptedSegmentLength();
}

// FloeDecryptor

size_t FloeDecryptor::getInputSize() const noexcept { return m_params.getEncryptedSegmentLength(); }

size_t FloeDecryptor::getOutputSize() const noexcept {
  return m_params.getPlaintextSegmentLength();
}

size_t FloeDecryptor::sizeOfLastOutput(size_t lastSegmentSize) const noexcept {
  return lastSegmentSize - SEGMENT_LENGTH_PREFIX - getNonceLength(m_params.getAead()) -
         getTagLength(m_params.getAead());
}

std::pair<FloeResult, std::unique_ptr<FloeDecryptor>> FloeDecryptor::create(
    const FloeKey& key, const absl::Span<const ub1>& aad,
    const absl::Span<const ub1>& header) noexcept {
  auto decryptor = std::unique_ptr<FloeDecryptor>(new FloeDecryptor());
  auto result = decryptor->initialize(key, aad, header);
  if (result != FloeResult::Success) {
    return {result, nullptr};
  } else {
    return {result, std::move(decryptor)};
  }
}

FloeResult FloeDecryptor::initialize(const sf::FloeKey& key, const absl::Span<const ub1>& aad,
                                     const absl::Span<const ub1>& header) noexcept {
  if (!key.isValid()) {
    return FloeResult::InvalidInput;
  }
  auto params = &(key.m_state->m_params);
  auto expectedEncodedParams = params->getEncoded();
  if (header.size() < params->getHeaderLength()) {
    return FloeResult::BadHeader;
  }
  // Check that the encoded params match what is in the header. This does not need to be constant
  // time. We're constant time anyway though.
  if (CRYPTO_memcmp(expectedEncodedParams->data(), header.data(), expectedEncodedParams->size()) !=
      0) {
    return FloeResult::BadHeader;
  }

  std::vector<ub1> aadVec(aad.begin(), aad.end());

  auto headerTag = &header[expectedEncodedParams->size() + params->getIvLength()];
  std::vector<ub1> iv;
  iv.insert(iv.end(), &header[expectedEncodedParams->size()], headerTag);
  auto tagAsKey = key.derive(iv, aadVec, PURPOSE_HEADER_TAG, HEADER_TAG_SIZE);
  auto tag = tagAsKey->getKey();
  // Check the header tag. This *must* be constant-time
  if (CRYPTO_memcmp(tag.data(), headerTag, tag.size()) != 0) {
    return FloeResult::BadTag;
  }
  auto messageKey = key.derive(iv, aadVec, PURPOSE_MESSAGE_KEY, getHashLength(params->getHash()));
  cryptorInitialize(iv, aadVec, std::move(messageKey));
  return FloeResult::Success;
}

FloeResult FloeDecryptor::processSegment(const absl::Span<const ub1>& input,
                                         absl::Span<ub1>& output) noexcept {
  if (m_messageKey == nullptr) {
    return FloeResult::NotInitialized;
  }

  if (m_closed) {
    return FloeResult::Closed;
  }
  // assert len(EncryptedSegment) == ENC_SEG_LEN
  if (input.size() != getInputSize()) {
    return FloeResult::InvalidInput;
  }
  if (output.size() < getOutputSize()) {
    return FloeResult::DataOverflow;
  }

  // assert BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF
  auto segmentLengthHeader = be2i4(input);

  if (segmentLengthHeader == getInputSize()) {
    // We've hit the last segment and our caller hasn't noticed.
    return processLastSegment(input, output);
  } else if (segmentLengthHeader != UB4_MAX) {
    return FloeResult::MalformedSegment;
  }

  // assert State.Counter != AEAD_MAX_SEGMENTS - 1
  if (m_counter == getMaxSegments(m_params.getAead()) - 1) {
    return FloeResult::SegmentOverflow;
  }

  // aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, State.Counter)
  useCurrentKey();

  ub1 rawSegmentAad[SEGMENT_AAD_SIZE];
  absl::Span<ub1> segmentAad(rawSegmentAad);
  buildSegmentAad(false, segmentAad);

  size_t outputSize = getOutputSize();
  FloeResult result =
      m_aeadCryptor->decrypt(input.subspan(SEGMENT_LENGTH_PREFIX), output, &outputSize, segmentAad);
  if (result != FloeResult::Success) {
    return result;
  }
  m_counter++;
  return FloeResult::Success;
}

FloeResult FloeDecryptor::processLastSegment(const absl::Span<const ub1>& input,
                                             absl::Span<ub1>& output) noexcept {
  if (m_messageKey == nullptr) {
    return FloeResult::NotInitialized;
  }

  if (m_closed) {
    return FloeResult::Closed;
  }
  // assert len(EncryptedSegment) >= AEAD_IV_LEN + AEAD_TAG_LEN + SEGMENT_LENGTH_PREFIX
  if (input.size() < getNonceLength(m_params.getAead()) + getTagLength(m_params.getAead()) +
                         SEGMENT_LENGTH_PREFIX) {
    return FloeResult::Truncated;
  }

  // assert len(EncryptedSegment) <= ENC_SEG_LEN
  if (input.size() > getInputSize()) {
    return FloeResult::MalformedSegment;
  }

  // assert BE2I(EncryptedSegment[:4]) == len(EncryptedSegment)
  ub4 expectedLength = be2i4(input);
  if (expectedLength != input.size()) {
    return FloeResult::MalformedSegment;
  }
  // aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, State.Counter)
  useCurrentKey();

  ub1 rawSegmentAad[SEGMENT_AAD_SIZE];
  absl::Span<ub1> segmentAad(rawSegmentAad);
  buildSegmentAad(true, segmentAad);
  size_t ciphertextSize = sizeOfLastOutput(input.size());
  FloeResult result = m_aeadCryptor->decrypt(input.subspan(SEGMENT_LENGTH_PREFIX), output,
                                             &ciphertextSize, segmentAad);
  if (result != FloeResult::Success) {
    return result;
  }
  m_closed = true;

  return FloeResult::Success;
}
}  // namespace sf
