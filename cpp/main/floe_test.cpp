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

#include "floe_test_shared.hpp"

// This file mostly focuses on error cases as the happy cases are covered by the KATs and bounce
// tests.

namespace sf {

const FloeParameterSpec PARAMS(FloeAead::AES_256_GCM, FloeHash::SHA_384, 64);
const char* HEADER_HEX =
    "00000000004000000020805f0152a4286ed9cf0fe9659611f6c9766e101170927576640a27e50c4590b0444d57bb9d"
    "e560dc64a78acc22810cba84dc49a30825e97b7e1b074e7c69c398";
const char* SEGMENT1_HEX =
    "ffffffff73b3b469d616f2669ddb89e8930450f159867de5a252dbbb24a4f6477d97d3ce9fc752537be0a4414beec7"
    "f587cc604abe893e34314add36a1763b8a";
const char* SEGMENT2_HEX =
    "ffffffff38b31dbfac7c629a1910b6508a27ab14bb7da2545fc186754a51a1f301b2e1957fcd119dbaa7fa571c9ed9"
    "817ddcd400245255f305d90f26b8a2a609";
const char* SEGMENT3_HEX = "00000023cb1121d1186a16b066081c08f65761c063cd45881e8f36d733bbe97fef2e23";
const std::vector<ub1> HEADER_RAW = hex_to_string(HEADER_HEX, strlen(HEADER_HEX));
const std::vector<ub1> SEGMENT1_RAW = hex_to_string(SEGMENT1_HEX, strlen(HEADER_HEX));
const std::vector<ub1> SEGMENT2_RAW = hex_to_string(SEGMENT2_HEX, strlen(HEADER_HEX));
const std::vector<ub1> SEGMENT3_RAW = hex_to_string(SEGMENT3_HEX, strlen(HEADER_HEX));
const absl::Span<const ub1> HEADER(HEADER_RAW);
const absl::Span<const ub1> SEGMENT1(SEGMENT1_RAW);
const absl::Span<const ub1> SEGMENT2(SEGMENT2_RAW);
const absl::Span<const ub1> SEGMENT3(SEGMENT3_RAW);
constexpr ub1 RAW_KEY[32] = {0};
const FloeKey KEY(RAW_KEY, PARAMS);

FloeResult decryptValidHeader() {
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, HEADER);
  CHECK_RETURN(result);
  CHECK_BOOL(decryptor != nullptr);
  return FloeResult::Success;
}

FloeResult longKeyInvalid() {
  ub1 rawLong[33] = {0};
  FloeKey longKey(rawLong, PARAMS);
  return longKey.isValid() ? FloeResult::Unexpected : FloeResult::Success;
}

FloeResult headerWithBadParams() {
  std::vector<ub1> localHeader(HEADER.begin(), HEADER.end());
  for (int x = 0; x < 10; x++) {
    localHeader[x] ^= 0x01;
    auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, localHeader);
    EXPECT_ERROR(result, FloeResult::BadHeader);
    CHECK_BOOL(decryptor == nullptr);
    localHeader[x] ^= 0x01;
  }
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, localHeader);
  CHECK_RETURN(result);
  CHECK_BOOL(decryptor != nullptr);
  return FloeResult::Success;
}

FloeResult headerWithBadIvOrTag() {
  std::vector<ub1> localHeader(HEADER.begin(), HEADER.end());
  for (int x = 10; x < localHeader.size(); x++) {
    localHeader[x] ^= 0x01;
    auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, localHeader);
    EXPECT_ERROR(result, FloeResult::BadTag);
    CHECK_BOOL(decryptor == nullptr);
    localHeader[x] ^= 0x01;
  }
  return FloeResult::Success;
}

FloeResult headerAloneCountsAsTruncated() {
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, HEADER);
  CHECK_RETURN(result);
  EXPECT_ERROR(decryptor->finish(), FloeResult::Truncated);
  CHECK_BOOL(!decryptor->isClosed());

  return FloeResult::Success;
}

FloeResult missingFinalSegmentIsTruncated() {
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, HEADER);

  CHECK_RETURN(result);
  std::vector<ub1> outVec;
  outVec.resize(KEY.getParameterSpec().getPlaintextSegmentLength(), 0);
  absl::Span<ub1> out(outVec);
  CHECK_RETURN(decryptor->processSegment(SEGMENT1, out));
  EXPECT_ERROR(decryptor->finish(), FloeResult::Truncated);
  CHECK_BOOL(!decryptor->isClosed());

  return FloeResult::Success;
}

FloeResult corruptedInnerSegment() {
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, HEADER);

  CHECK_RETURN(result);
  std::vector<ub1> outVec;

  outVec.resize(KEY.getParameterSpec().getPlaintextSegmentLength(), 0);
  absl::Span<ub1> out(outVec);

  // First four bytes are special as they are the non-terminal indicator
  std::vector<ub1> localSegment = SEGMENT1_RAW;
  for (int x = 0; x < localSegment.size(); x++) {
    localSegment[x] ^= 0x01;
    FloeResult expectedError = x < 4 ? FloeResult::MalformedSegment : FloeResult::BadTag;
    EXPECT_ERROR(decryptor->processSegment(localSegment, out), expectedError);
    localSegment[x] ^= 0x01;
  }
  // We didn't break anything
  CHECK_RETURN(decryptor->processSegment(SEGMENT1, out));
  return FloeResult::Success;
}

FloeResult corruptedFinalSegment() {
  auto [result, decryptor] = FloeDecryptor::create(KEY, AAD, HEADER);
  CHECK_RETURN(result);
  std::vector<ub1> outVec;
  outVec.resize(KEY.getParameterSpec().getPlaintextSegmentLength(), 0);
  absl::Span<ub1> out(outVec);

  CHECK_RETURN(decryptor->processSegment(SEGMENT1, out));
  CHECK_RETURN(decryptor->processSegment(SEGMENT2, out));

  std::vector<ub1> localSegment = SEGMENT3_RAW;

  // First four bytes are special as they are the length indicator
  for (int x = 0; x < localSegment.size(); x++) {
    localSegment[x] ^= 0x01;
    FloeResult expectedError = x < 4 ? FloeResult::MalformedSegment : FloeResult::BadTag;
    EXPECT_ERROR(decryptor->processLastSegment(localSegment, out), expectedError);
    localSegment[x] ^= 0x01;
  }
  CHECK_RETURN(decryptor->processLastSegment(SEGMENT3, out));

  return FloeResult::Success;
}

FloeResult cannotUseAfterClose() {
  auto [eResult, encryptor] = FloeEncryptor::create(KEY, AAD);
  CHECK_RETURN(eResult);

  auto header = encryptor->getHeader();
  std::vector<ub1> scratch;
  scratch.resize(PARAMS.getEncryptedSegmentLength(), 0);
  absl::Span<ub1> scratchSpan;
  std::vector<ub1> segment;
  segment.resize(encryptor->sizeOfLastOutput(0));
  absl::Span<ub1> segmentSpan(segment);
  absl::Span<ub1> empty;
  CHECK_RETURN(encryptor->processLastSegment(empty, segmentSpan));
  CHECK_BOOL(encryptor->isClosed());

  EXPECT_ERROR(encryptor->processSegment(scratchSpan.subspan(0, PARAMS.getPlaintextSegmentLength()),
                                         scratchSpan),
               FloeResult::Closed);
  EXPECT_ERROR(encryptor->processLastSegment(empty, scratchSpan), FloeResult::Closed);

  auto [dResult, decryptor] = FloeDecryptor::create(KEY, AAD, header);
  CHECK_RETURN(dResult);
  // Also verifies that we can decrypt empty plaintext to a nullptr
  CHECK_RETURN(decryptor->processLastSegment(segment, empty));
  CHECK_BOOL(decryptor->isClosed());

  EXPECT_ERROR(decryptor->processSegment(scratchSpan, scratchSpan), FloeResult::Closed);
  EXPECT_ERROR(decryptor->processLastSegment(segment, scratchSpan), FloeResult::Closed);
  return FloeResult::Success;
}

}  // namespace sf
int main(int argc, char** argv) {
  int summaryResult = 0;
  RUN_TEST(sf::decryptValidHeader());
  RUN_TEST(sf::longKeyInvalid());
  RUN_TEST(sf::headerWithBadParams());
  RUN_TEST(sf::headerWithBadIvOrTag());
  RUN_TEST(sf::headerAloneCountsAsTruncated());
  RUN_TEST(sf::missingFinalSegmentIsTruncated());
  RUN_TEST(sf::corruptedInnerSegment());
  RUN_TEST(sf::corruptedFinalSegment());
  RUN_TEST(sf::cannotUseAfterClose());
  return summaryResult;
}
