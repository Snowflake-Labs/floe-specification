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

#include "floe_test_shared.hpp"

#include <cstring>
#include <random>

using std::cout;
using std::endl;

namespace sf {
const ub1* RAW_AAD = reinterpret_cast<const ub1*>("This is AAD");
const absl::Span<const ub1> AAD(RAW_AAD, strlen(reinterpret_cast<const char*>(RAW_AAD)));

FloeResult decryptKat(std::string& testName, FloeParameterSpec param,
                      const absl::Span<const ub1>& ct, std::vector<ub1>& out) {
  std::vector<ub1> rawKey;
  // TODO: Fix this if we ever handle multiple rawKey lengths
  rawKey.resize(32, 0);
  auto key = FloeKey(rawKey, param);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, ct);

  CHECK_RETURN_NAME(testName, result);

  for (size_t offset = param.getHeaderLength(); offset < ct.size();
       offset += param.getEncryptedSegmentLength()) {
    std::vector<ub1> segment;

    if (offset + param.getEncryptedSegmentLength() >= ct.size()) {
      auto lastCtSegmentSize = ct.size() - offset;
      segment.resize(decryptor->sizeOfLastOutput(lastCtSegmentSize), 0);
      absl::Span<ub1> segmentSpan(segment);
      CHECK_RETURN_NAME(testName, decryptor->processLastSegment(ct.subspan(offset), segmentSpan));
    } else {
      segment.resize(param.getPlaintextSegmentLength());
      absl::Span<ub1> segmentSpan(segment);

      CHECK_RETURN_NAME(
          testName, decryptor->processSegment(ct.subspan(offset, param.getEncryptedSegmentLength()),
                                              segmentSpan));
    }
    out.insert(out.end(), segment.begin(), segment.end());
  }

  CHECK_RETURN_NAME(testName, decryptor->finish());
  return FloeResult::Success;
}

FloeResult encryptKat(std::string& testName, FloeParameterSpec param, size_t segCount,
                      std::vector<ub1>& pt, std::vector<ub1>& ct) {
  std::vector<ub1> rawKey;
  // TODO: Fix this if we ever handle multiple rawKey lengths
  rawKey.resize(32, 0);
  auto key = FloeKey(rawKey, param);
  pt.resize(segCount * param.getPlaintextSegmentLength() + 3, 0);

  static std::uniform_int_distribution<int> distribution(std::numeric_limits<int>::min(),
                                                         std::numeric_limits<int>::max());
  static std::default_random_engine generator;  // This is not secure but doesn't matter

  std::generate(pt.begin(), pt.end(), []() { return distribution(generator); });
  absl::Span<const ub1> ptSpan(pt);

  auto [result, encryptor] = FloeEncryptor::create(key, AAD);
  CHECK_RETURN_NAME(testName, result);
  auto header = encryptor->getHeader();
  ct.insert(ct.end(), header.begin(), header.end());
  for (size_t offset = 0; offset < pt.size(); offset += param.getPlaintextSegmentLength()) {
    std::vector<ub1> segment;
    if (offset + param.getPlaintextSegmentLength() >= pt.size()) {
      size_t lastPtSegmentLength = pt.size() - offset;
      segment.resize(encryptor->sizeOfLastOutput(lastPtSegmentLength), 0);
      absl::Span<ub1> segmentSpan(segment);
      CHECK_RETURN_NAME(testName,
                        encryptor->processLastSegment(ptSpan.subspan(offset), segmentSpan));
    } else {
      segment.resize(param.getEncryptedSegmentLength(), 0);
      absl::Span<ub1> segmentSpan(segment);
      CHECK_RETURN_NAME(
          testName, encryptor->processSegment(
                        ptSpan.subspan(offset, param.getPlaintextSegmentLength()), segmentSpan));
    }
    ct.insert(ct.end(), segment.begin(), segment.end());
  }
  return FloeResult::Success;
}

int hex_value(unsigned char hex_digit)

{
  static const signed char hex_values[256] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10,
      11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };
  int value = hex_values[hex_digit];
  if (value == -1) throw std::invalid_argument("invalid hex digit");
  return value;
}

std::vector<ub1> hex_to_string(const std::string& input, size_t i) {
  const auto len = input.length();
  if (len & 1) throw std::invalid_argument("odd length");

  std::vector<ub1> output;
  output.reserve(len / 2);
  for (auto it = input.begin(); it != input.end();) {
    int hi = hex_value(*it++);
    int lo = hex_value(*it++);
    output.push_back(hi << 4 | lo);
  }
  return output;
}
std::string string_to_hex(const std::vector<ub1>& vec) {
  return string_to_hex(vec.data(), vec.size());
}

std::string string_to_hex(const ub1* input, size_t len) {
  static const char hex_digits[] = "0123456789ABCDEF";

  std::string output;
  output.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    ub1 c = input[i];
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output;
}
}  // namespace sf
