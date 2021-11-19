// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// -----------------------------------------------------------------------------
//
//  Implementation of FSST
//
// Author: Skal (pascal.massimino@gmail.com)

//------------------------------------------------------------------------------
#ifndef LIBFFSST_H_
#define LIBFFSST_H_

#include <cassert>
#include <cinttypes>
#include <cstddef>

#include <string>

struct CodeTable {
  uint64_t codes_[255];
  uint8_t len_[255];
};

extern bool Analyze(const std::string input, CodeTable& codes);
extern std::string Compress(const std::string input, const CodeTable& codes);
extern std::string Decompress(const std::string input, CodeTable& codes);

#endif  // LIBFFSST_H_
