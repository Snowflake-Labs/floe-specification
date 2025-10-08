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

#include <cstring>
#include <iostream>

#include "absl/types/span.h"
#include "floe.hpp"
#include "floe_test_shared.hpp"
#include "platform.hpp"

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Expected two arguments: ./sample_cli <encrypt|decrypt> <hexkey>" << std::endl;
    return -1;
  }
  auto command = argv[1];
  if (strcmp(command, "encrypt") != 0 && strcmp(command, "decrypt") != 0) {
    std::cerr << "Expected two arguments: ./sample_cli <encrypt|decrypt> <hexkey>" << std::endl;
    return -1;
  }
  if (strlen(argv[2]) != 64) {
    std::cerr << "Expected two arguments: ./sample_cli <encrypt|decrypt> <hexkey>" << std::endl;
    return -1;
  }
  auto binKey = sf::hex_to_string(argv[2], strlen(argv[2]));
  auto params = sf::FloeParameterSpec::GCM256_IV256_4K();
  sf::FloeKey floeKey = sf::FloeKey(binKey, params);

  sf::FloeResult result = sf::FloeResult::Success;
  std::unique_ptr<sf::FloeCryptor> cryptor;
  std::vector<ub1> bufInRaw;
  bufInRaw.resize(params.getEncryptedSegmentLength(), 0);
  absl::Span<ub1> bufIn(bufInRaw);
  std::vector<ub1> bufOutRaw;
  bufOutRaw.resize(params.getEncryptedSegmentLength(), 0);
  absl::Span<ub1> bufOut(bufOutRaw);
  const absl::Span<ub1> emptySpan;
  bool isEncrypting;
  if (strcmp(command, "encrypt") == 0) {
    isEncrypting = true;
    auto [result, encryptor] = sf::FloeEncryptor::create(floeKey, emptySpan);
    if (result != sf::FloeResult::Success) {
      std::cerr << "Error initializing encryptor: " << sf::floeErrorMessage(result) << std::endl;
      return -1;
    }
    bufIn.remove_suffix(32);
    auto header = encryptor->getHeader();
    std::cout.write(reinterpret_cast<const char*>(header.data()), header.size());
    cryptor = std::move(encryptor);
  } else {
    isEncrypting = false;
    std::cin.read(reinterpret_cast<char*>(bufIn.data()), params.getHeaderLength());
    auto [result, decryptor] = sf::FloeDecryptor::create(floeKey, emptySpan, bufIn);
    if (result != sf::FloeResult::Success) {
      std::cerr << "Error initializing decryptor: " << sf::floeErrorMessage(result) << std::endl;
      return -1;
    }
    bufOut.remove_suffix(32);
    cryptor = std::move(decryptor);
  }

  while (true) {
    std::cin.read(reinterpret_cast<char*>(bufIn.data()), cryptor->getInputSize());
    auto bytesRead = std::cin.gcount();
    size_t bytesWritten = 0;
    if (bytesRead != cryptor->getInputSize()) {
      // We're at the end
      bytesWritten = cryptor->sizeOfLastOutput(bytesRead);
      result = cryptor->processLastSegment(bufIn.subspan(0, bytesRead), bufOut);
      if (result != sf::FloeResult::Success) {
        std::cerr << "Error processing last segment: " << sf::floeErrorMessage(result) << std::endl;
        return -1;
      }
      std::cout.write(reinterpret_cast<const char*>(bufOut.data()), bytesWritten);
      break;
    } else {
      bytesWritten = cryptor->getOutputSize();
      result = cryptor->processSegment(bufIn, bufOut);
      if (result != sf::FloeResult::Success) {
        std::cerr << "Error processing segment: " << sf::floeErrorMessage(result) << std::endl;
        return -1;
      }
      std::cout.write(reinterpret_cast<const char*>(bufOut.data()), bytesWritten);
    }
  }

  // In the encryption case, we may not have found the final segment and so need to output it
  if (isEncrypting && !cryptor->isClosed()) {
    auto bytesWritten = cryptor->sizeOfLastOutput(0);
    result = cryptor->processLastSegment(bufIn.subspan(0, 0), bufOut);
    if (result != sf::FloeResult::Success) {
      std::cerr << "Error processing last segment: " << sf::floeErrorMessage(result) << std::endl;
      return -1;
    }
    std::cout.write(reinterpret_cast<const char*>(bufOut.data()), bytesWritten);
  }

  result = cryptor->finish();
  if (result != sf::FloeResult::Success) {
    std::cerr << "Error calling finish: " << sf::floeErrorMessage(result) << std::endl;
    return -1;
  }
  return 0;
}
