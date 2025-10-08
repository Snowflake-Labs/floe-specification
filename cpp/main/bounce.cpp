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

#import "floe_test_shared.hpp"

namespace sf {
namespace {
FloeResult testBounce(std::string testName, FloeParameterSpec params, size_t segCount) {
  std::vector<ub1> plaintext;
  std::vector<ub1> ciphertext;
  CHECK_RETURN_NAME(testName, encryptKat(testName, params, segCount, plaintext, ciphertext));
  std::vector<ub1> decrypted;
  absl::Span<const ub1> ctSpan(ciphertext);
  CHECK_RETURN_NAME(testName, decryptKat(testName, params, ctSpan, decrypted));
  if (decrypted != plaintext) {
    std::cout << "\x1b[31;1mFAIL\x1b[0m: Test " << testName << " failed due to plaintext mismatch"
              << std::endl;
    return FloeResult::Unexpected;
  }
  return FloeResult::Success;
}
}  // anonymous namespace
}  // namespace sf

int main(int argc, char** argv) {
  int summaryResult = 0;
  auto smallSegment = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 64);
  auto rotation = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 40, -4);

  RUN_TEST(sf::testBounce("GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M(), 2));
  RUN_TEST(sf::testBounce("GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K(), 2));
  RUN_TEST(sf::testBounce("GCM256_IV256_64", smallSegment, 2));
  RUN_TEST(sf::testBounce("rotation", rotation, 10));

  return summaryResult;
}
