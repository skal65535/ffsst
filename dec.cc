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

// Format:
//  per block:
//    * 3 bytes for size
//    * 8 bytes for signature
//    * 1 bit for 'IsZeroTerminated'  (in 1 byte)
//    * 8 bytes of histoLen[] for lengths 1 to 8
//    * the codes for lengths 2,3,4,5,6,7,8,1

#include "ffsst.h"

#include <cassert>
#include <cstring>

//------------------------------------------------------------------------------
// Decoding

namespace {

const uint8_t kVersionString[4] = { 0x0a, 0x14, 0x34, 0x01 };

struct DecodeTable {
  uint8_t codes_[255][8];
  uint8_t len_[255];
  bool is_zero_terminated_ = false;

  uint32_t ReadParams(const char input[], uint32_t input_size);
};

uint32_t DecodeTable::ReadParams(const char input[], uint32_t input_size) {
  if (input_size < 3 + 8 + 1 + 8) return 0;
  if (memcmp(input + 4 + 3, kVersionString, 4)) return 0;

  is_zero_terminated_ = input[3 + 8] & 1;
  uint32_t hlens[8];
  for (uint32_t i = 0; i < 8; ++i) hlens[i] = (uint8_t)input[3 + 8 + 1 + i];

  len_[0] = 1;
  codes_[0][0] = 0;   // code: '\0'
  uint32_t code = is_zero_terminated_ ? 1 : 0;
  if (is_zero_terminated_) {
    if (hlens[0] == 0) return 0;
    hlens[0] -= 1;
  }

  uint32_t pos = 3 + 8 + 1 + 8;
  for (uint32_t code_length : { 2, 3, 4, 5, 6, 7, 8, 1 }) {
    const uint32_t num_codes = hlens[code_length - 1];
    if (pos + num_codes * code_length > input_size) return 0;
    for (uint32_t j = 0; j < num_codes; ++j, ++code) {
      memcpy(codes_[code], input + pos, code_length);
      len_[code] = code_length;
      pos += code_length;
    }
  }

  fprintf(stderr, "Num codes: %d  (code-len: ", code);
  for (const auto& h : hlens) fprintf(stderr, "[%d]", h);
  fprintf(stderr, ")\nIs_Zero_Terminated: %d\n", is_zero_terminated_);

  for (; code < 255; ++code) len_[code] = 0;  // robustness: complete the array
  return pos;
}

}  // namespace

namespace ffsst {

const size_t kMaxBlkSize = 1u << 10;

bool Decompress(const std::string input, std::string& output) {
  output.clear();

  char buf[kMaxBlkSize + 1];
  uint32_t in_pos = 0;
  while (in_pos + 3 < input.size()) {
    const uint32_t in_size = (((uint8_t)input[in_pos + 0]) << 16)
                           | (((uint8_t)input[in_pos + 1]) <<  8)
                           | (((uint8_t)input[in_pos + 2]) <<  0);
    if (in_pos + in_size > input.size()) return false;

    DecodeTable codes;
    const uint32_t c = codes.ReadParams(&input[in_pos], in_size);
    if (c == 0) return false;
    
    uint32_t out_pos = 0, blk_size = 0;
    for (uint32_t p = c; p < in_size; ++p) {
      const uint8_t v = (uint8_t)input[in_pos + p];
      if (v == 255u) {
        if (++p >= in_size) return false;
        buf[out_pos++] = input[in_pos + p];
      } else {
        const uint32_t l = codes.len_[v];
        if (l == 0) return false;
        memcpy(buf + out_pos, &codes.codes_[v], l);
        out_pos += l;
      }
      if (out_pos >= kMaxBlkSize) {
        blk_size += out_pos;
        output.append(buf, out_pos);
        out_pos = 0;
      }
    }
    blk_size += out_pos;
    if (out_pos > 0) output.append(buf, out_pos);
    in_pos += in_size;

    fprintf(stderr, "Size: in=%d out=%d (%.1f%%)\n",
            in_size, blk_size, 100. * in_size / blk_size);
  }
  return true;
}

}  // namespace ffsst
