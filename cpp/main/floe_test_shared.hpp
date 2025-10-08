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
#include "floe.hpp"
#include "platform.hpp"
#define CHECK_RETURN(x) CHECK_RETURN_NAME(__func__, x)

#define CHECK_RETURN_NAME(name, x)                                                            \
  do {                                                                                        \
    sf::FloeResult tmpReturn = x;                                                             \
    if (tmpReturn != sf::FloeResult::Success) {                                               \
      std::cout << "\x1b[31;1mFAIL\x1b[0m: Failed " << name << " at " << __FILE__ << "#"      \
                << __LINE__ << " with code " << sf::floeErrorMessage(tmpReturn) << std::endl; \
      return tmpReturn;                                                                       \
    }                                                                                         \
  } while (0)

#define CHECK_BOOL(x) CHECK_BOOL_NAME(__func__, x)

#define CHECK_BOOL_NAME(name, x)                                                         \
  do {                                                                                   \
    bool tmpReturn = x;                                                                  \
    if (!tmpReturn) {                                                                    \
      std::cout << "\x1b[31;1mFAIL\x1b[0m: Failed " << name << " at " << __FILE__ << "#" \
                << __LINE__ << std::endl;                                                \
      return sf::FloeResult::Unexpected;                                                 \
    }                                                                                    \
  } while (0)

#define EXPECT_ERROR(x, errCode) EXPECT_ERROR_NAME(__func__, x, errCode)

#define EXPECT_ERROR_NAME(name, x, errCode)                                                   \
  do {                                                                                        \
    FloeResult tmpReturn = x;                                                                 \
    if (tmpReturn != errCode) {                                                               \
      std::cout << "\x1b[31;1mFAIL\x1b[0m: Failed " << name << " at " << __FILE__ << "#"      \
                << __LINE__ << " with code " << sf::floeErrorMessage(tmpReturn) << std::endl; \
      return sf::FloeResult::Unexpected;                                                      \
    }                                                                                         \
  } while (0)

#define RUN_TEST(test)                                              \
  do {                                                              \
    sf::FloeResult testResult = test;                               \
    if (testResult == sf::FloeResult::Success) {                    \
      std::cout << "\x1b[32;1mPASS\x1b[0m: " << #test << std::endl; \
    } else {                                                        \
      summaryResult = -1;                                           \
    }                                                               \
  } while (0)

namespace sf {
extern const ub1* RAW_AAD;
extern const absl::Span<const ub1> AAD;

const std::string KAT_BASE = "kats/";

FloeResult decryptKat(std::string& testName, FloeParameterSpec param,
                      const absl::Span<const ub1>& in, std::vector<ub1>& out);
FloeResult encryptKat(std::string& testName, FloeParameterSpec param, size_t segCount,
                      std::vector<ub1>& pt, std::vector<ub1>& ct);

std::vector<ub1> hex_to_string(const std::string& input, size_t i);
std::string string_to_hex(const std::vector<ub1>& vec);
std::string string_to_hex(const ub1* input, size_t len);

}  // namespace sf
