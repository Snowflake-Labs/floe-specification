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

using std::cerr;
using std::endl;
using std::string;

namespace sf {
namespace {
void writeKat(string katName, FloeParameterSpec params, int segCount, string& base) {
  std::vector<ub1> plaintext;
  std::vector<ub1> ciphertext;
  assert(encryptKat(katName, params, segCount, plaintext, ciphertext) == FloeResult::Success);

  auto ctOut = std::ofstream(base + katName + "_ct.txt");
  auto ctHex = string_to_hex(ciphertext);
  ctOut.write(ctHex.data(), ctHex.size());
  ctOut.close();

  auto ptOut = std::ofstream(base + katName + "_pt.txt");
  auto ptHex = string_to_hex(plaintext);
  ptOut.write(ptHex.data(), ptHex.size());
  ptOut.close();
}
}  // anonymous namespace
}  // namespace sf
int main(int argc, char** argv) {
  if (argc < 2) {
    cerr << "Must pass output directory" << endl;
  }
  auto smallSegment = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 64);
  auto rotation = sf::FloeParameterSpec(sf::FloeAead::AES_256_GCM, sf::FloeHash::SHA_384, 40, -4);
  std::string base(argv[1]);
  sf::writeKat("cpp_GCM256_IV256_1M", sf::FloeParameterSpec::GCM256_IV256_1M(), 2, base);
  sf::writeKat("cpp_GCM256_IV256_4K", sf::FloeParameterSpec::GCM256_IV256_4K(), 2, base);
  sf::writeKat("cpp_GCM256_IV256_64", smallSegment, 2, base);
  sf::writeKat("cpp_rotation", rotation, 10, base);
}
