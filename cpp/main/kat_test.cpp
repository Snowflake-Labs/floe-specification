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

#include <fstream>
#include <iostream>
#include <string>

#include "floe.hpp"
#include "floe_test_shared.hpp"
#include "platform.hpp"

using ::std::cout;
using ::std::endl;
using ::std::vector;

namespace sf {

std::vector<ub1> fromHexFile(std::string fileName) {
  std::vector<ub1> result;
  auto stream = std::ifstream(fileName.data());
  if (!stream.is_open()) {
    cout << "Unable to open file: " << fileName << endl;
    assert(false);
  }
  std::string buf(2, '\0');
  while (stream.read(buf.data(), buf.size())) {
    auto bin = hex_to_string(buf, 0);
    result.insert(result.end(), bin.begin(), bin.end());
  }

  stream.close();
  return result;
}

FloeResult testKat(std::string testName, FloeParameterSpec param) {
  auto ct = fromHexFile(KAT_BASE + testName + "_ct.txt");
  auto pt = fromHexFile(KAT_BASE + testName + "_pt.txt");
  vector<ub1> decrypted;

  CHECK_RETURN_NAME(testName, decryptKat(testName, param, ct, decrypted));

  if (decrypted != pt) {
    cout << "\x1b[31;1mFAIL\x1b[0m: Test " << testName << " failed due to plaintext mismatch"
         << endl;
    return FloeResult::Unexpected;
  }
  return FloeResult::Success;
}
}  // namespace sf

int main(int argc, char** argv) {
  int summaryResult = 0;
  auto smallSegment = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 64);
  auto rotation = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 40, -4);
  RUN_TEST(testKat("java_GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M()));
  RUN_TEST(testKat("java_GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K()));
  RUN_TEST(testKat("java_GCM256_IV256_64", smallSegment));
  RUN_TEST(testKat("java_rotation", rotation));

  RUN_TEST(testKat("go_GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M()));
  RUN_TEST(testKat("go_GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K()));
  RUN_TEST(testKat("go_GCM256_IV256_64", smallSegment));
  RUN_TEST(testKat("go_rotation", rotation));

  RUN_TEST(testKat("pub_java_GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M()));
  RUN_TEST(testKat("pub_java_GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K()));
  RUN_TEST(testKat("pub_java_GCM256_IV256_64", smallSegment));
  RUN_TEST(testKat("pub_java_rotation", rotation));

  RUN_TEST(testKat("cpp_GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M()));
  RUN_TEST(testKat("cpp_GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K()));
  RUN_TEST(testKat("cpp_GCM256_IV256_64", smallSegment));
  RUN_TEST(testKat("cpp_rotation", rotation));

  // There are a few Java generated only KATs
  auto segmentTestParams = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 40);
  RUN_TEST(testKat("java_lastSegAligned", segmentTestParams));
  RUN_TEST(testKat("java_lastSegEmpty", segmentTestParams));
  return summaryResult;
}
