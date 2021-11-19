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
#include <algorithm>
#include <vector>
#include <map>

namespace {

const uint8_t kVersionString[8] = {
  0x01 /*endian marker*/,
  0xff /*nSymbols*/,
  0x01 /*terminator*/,
  0x00 /*suffixLim*/,
  0x0a, 0x14, 0x34, 0x01
};

struct CodeTable {
  uint8_t codes_[255][8];
  uint8_t len_[255] = { 0 };
  uint8_t num_codes_ = 0;
  uint8_t hlens_[8] = { 0 };   // histogram of lengths 1,2,...,8
  uint8_t map_[256];   // index of codes sorted in length 2,3,4,5,6,7,8,1 order
  bool is_zero_terminated_ = false;

 public:
  void Print() const;
  uint32_t HeaderSize() const;
  void Clear();
  void MakeHistos();
};

//------------------------------------------------------------------------------
// encoding

const size_t kMaxBlkSize = 1u << 16;

bool WriteParams(const CodeTable& table, uint32_t size, std::string& output) {
  char tmp[3 + 8 + 1 + 8] = { 0 };
  std::vector<uint8_t> codes[8];  // for len 1..8
  if (size >= (1u << 24)) return false;
  tmp[0] = (size >> 16) & 0xff;
  tmp[1] = (size >>  8) & 0xff;
  tmp[2] = (size >>  0) & 0xff;
  memcpy(tmp + 3, kVersionString, 8 * sizeof(kVersionString[0]));
  if (table.is_zero_terminated_) tmp[3 + 8] |= 1;
  if (table.num_codes_ > 255) return false;
  for (uint32_t i = 0; i < table.num_codes_; ++i) {
    const uint32_t len = table.len_[i];
    if (len > 8 || len == 0) return false;
    const uint32_t slot1 = len - 1;
    const uint32_t slot2 = (len - 2) & 7;
    ++tmp[3 + 8 + 1 + slot1];
    const uint8_t* const src = table.codes_[i];
    codes[slot2].insert(codes[slot2].end(), src, src + len);
  }
  output.append(tmp, sizeof(tmp));
  for (const auto& v : codes) output.append((const char*)v.data(), v.size());
  for (uint32_t l : { 1, 2, 3, 4, 5, 6, 7, 8 }) {
    printf("code-len=%d, %d codes\n", l, tmp[3 + 8 + 1 + (l - 1)]);
  }
  return true;
}

//------------------------------------------------------------------------------
// Analysis

struct ACode {
  uint32_t rank_ = 0;
  uint8_t code_[8] = { 0 };
  uint8_t len_ = 0;
  uint32_t freq_ = 0;

  uint64_t code() const { return *(uint64_t*)code_; }  // endianess!
  bool operator<(const ACode& other) const {
    const uint32_t s0 = freq_ * len_, s1 = other.freq_ * other.len_;
    if (s0 != s1) return (s0 > s1);
    return (rank_ < other.rank_);
  }
};

void FinalizeTable(ACode codes[], uint32_t num_codes, CodeTable& table) {
  std::sort(codes, codes + num_codes);

  while (num_codes > 0 && codes[num_codes - 1].freq_ == 0) --num_codes;
  // least used code will be escaped if needed.
  if (num_codes >= 256) num_codes = 255;

  table.num_codes_ = num_codes;
  table.is_zero_terminated_ = false;
  for (uint32_t i = 0; i < num_codes; ++i) {
    table.len_[i] = codes[i].len_;
    memcpy(table.codes_[i], codes[i].code_, 8);
  }
  printf("Num_Syms: %d\n", num_codes);
  for (uint32_t i = 0; i < num_codes; ++i) {
    printf("#0x%16lx: f=%u (l=%d)\n",
           codes[i].code(), codes[i].freq_, codes[i].len_);
  }
  table.MakeHistos();
  table.Print();
}
  
bool Analyze(const uint8_t* input, uint32_t in_len, CodeTable& table,
             int effort) {
  table.Clear();
  if (effort == 0) return true;

  if (effort == 1) {
    ACode codes[256];
    for (uint32_t i = 0; i < in_len; ++i) ++codes[input[i]].freq_;

    uint32_t num_codes = 0;
    for (uint32_t i = 0; i < 256; ++i) {
      auto& C = codes[i];
      if (C.freq_) {
        C.rank_ = num_codes++;
        C.code_[0] = i;
        C.len_ = 1;
      }
    }
    FinalizeTable(codes, 256, table);
  } else {
    std::map<std::string, uint32_t> counts;
    for (uint32_t i = 0; i < in_len; ++i) {
      for (uint32_t j = 1; j <= 8; ++j) {
        if (i + j > in_len) break;
        const std::string str((char*)input + i, j);
        ++counts[str];
      }
    }
    printf("counts: size=%u / %u\n", counts.size(), in_len);
    std::vector<ACode> codes(counts.size());
    uint32_t i = 0;
    for (auto it = counts.begin(); it != counts.end(); ++it) {
      auto& C = codes[i];
      C.rank_ = i;
      C.freq_ = it->second;
      C.len_ = it->first.size();
      memcpy(C.code_, it->first.data(), C.len_ * sizeof(C.code_[0]));
      ++i;
    }
    FinalizeTable(codes.data(), codes.size(), table);
  }
  return true;
}

//------------------------------------------------------------------------------
// tmp buffer size.
static const size_t kMaxBuf = 8192;

struct Indexer {
  uint8_t num_[256];     // number of sequences starting with 'idx'
  uint8_t pos_[256];     // where the sequence starts
  uint8_t seq_[256];     // the sequence
  const CodeTable& tbl_;

  Indexer(const CodeTable& tbl) : tbl_(tbl) {
    memset(num_, 0, sizeof(num_));
    for (uint32_t i = 0; i < tbl.num_codes_; ++i) {
      const uint8_t idx = tbl.codes_[i][0];
      ++num_[idx];
    }
    uint8_t p = 0;
    for (uint32_t c = 0; c < 256; ++c) {
      pos_[c] = p;
      p += num_[c];
    }
    uint8_t pos[256];
    memcpy(pos, pos_, sizeof(pos));
    for (uint32_t i = 0; i < tbl.num_codes_; ++i) {
      const uint8_t idx = tbl.codes_[i][0];
      seq_[pos[idx]++] = i;
    }
  }
  uint8_t Match(const uint8_t input[], uint32_t max_len) const {
    const uint8_t idx = input[0];
    const uint8_t num = num_[idx];
    const uint8_t* seq = &seq_[pos_[idx]];
    uint32_t best_len = 0;
    uint32_t best_code = 255;
    for (uint32_t p = 0; p < num; ++p) {
      const uint32_t c = seq[p];
      const uint32_t len = tbl_.len_[c];
      if (len <= max_len && len > best_len) {
        if (!memcmp(input, tbl_.codes_[c], len)) {
          best_len = len;
          best_code = c;
        }
      }
    }
    return best_code;
  }
};

// basic x2 coding
uint32_t CodeBlk0(const uint8_t* input, uint32_t in_len, CodeTable& codes,
                  std::string& output) {
  size_t pos = 0;
  char tmp[kMaxBuf + 1];
  for (uint32_t p = 0; p < in_len; ++p) {
    tmp[pos++] = (char)255;
    tmp[pos++] = input[p];
    if (pos >= kMaxBuf) {
      output.append(tmp, pos);
      pos = 0;
    }
  }
  if (pos > 0) output.append(tmp, pos);
  return output.size() + codes.HeaderSize();
}

// greedy coding
uint32_t CodeBlk1(const uint8_t* input, uint32_t in_len, CodeTable& codes,
                  std::string& output) {
  size_t pos = 0;
  char tmp[kMaxBuf + 1];
  Indexer idx(codes);
  for (uint32_t p = 0; p < in_len; ) {
    const uint8_t code = idx.Match(input + p, std::min(in_len - p, 8u));
    tmp[pos++] = codes.map_[code];
    if (code == 255) {
      tmp[pos++] = input[p];
      p += 1;
    } else {
      p += codes.len_[code];
    }
    if (pos >= kMaxBuf) {
      output.append(tmp, pos);
      pos = 0;
    }
  }
  if (pos > 0) output.append(tmp, pos);
  return output.size() + codes.HeaderSize();
}

void CodeTable::Clear() {
  num_codes_ = 0;
  memset(len_, 0, sizeof(len_));
}

void CodeTable::MakeHistos() {
  memset(hlens_, 0, sizeof(hlens_));
  for (uint32_t i = 0; i < num_codes_; ++i) ++hlens_[len_[i] - 1];
  uint8_t pos[8];
  uint8_t p = 0;
  for (uint32_t l = 1; l <= 8; ++l) {
    pos[l - 1] = p;
    p += hlens_[l & 7];
  }
  for (uint32_t i = 0; i < num_codes_; ++i) {
    map_[i] = pos[(len_[i] - 2) & 7]++;
  }
  map_[255] = 255;   // escape
}

uint32_t CodeTable::HeaderSize() const {
  uint32_t size = 3 + 8 + 1 + 8;  // blk-size + version + byte + lens
  for (uint32_t i = 0; i < num_codes_; ++i) size += len_[i];
  return size;  
}

}  // namespace

namespace ffsst {

bool Compress(const std::string input, std::string& output,
              int effort) {
  output.clear();
  uint32_t in_pos = 0;
  while (in_pos < input.size()) {
    const size_t blk_size = std::min(input.size() - in_pos, kMaxBlkSize);
    const uint8_t* const src = (const uint8_t*)&input[in_pos];

    CodeTable codes;
    if (!Analyze(src, blk_size, codes, effort)) return false;

    std::string tmp;
    const size_t out_size =
      (effort == 0) ? CodeBlk0(src, blk_size, codes, tmp)
                    : CodeBlk1(src, blk_size, codes, tmp);
    if (!WriteParams(codes, out_size, output)) {
      fprintf(stderr, "Bad WriteParams()!\n");
      return false;
    }
    printf("blk_size: %u bytes, out_size: %u bytes\n",
           (uint32_t)blk_size, (uint32_t)out_size);
    output += tmp;
    in_pos += blk_size;
  }
  return true;
}

}  // namespace ffsst

//------------------------------------------------------------------------------
// Decoding

namespace {

uint32_t ReadParams(const char input[], uint32_t input_size,
                    CodeTable& codes) {
  if (input_size < 8 + 1 + 8) return 0;
  if (memcmp(input + 4, kVersionString + 4, 4)) return 0;
  codes.is_zero_terminated_ = (uint8_t)input[8] & 1;

  uint32_t hlens[8];
  for (uint32_t i = 0; i < 8; ++i) hlens[i] = (uint8_t)input[8 + 1 + i];

  codes.len_[0] = 1;
  codes.codes_[0][0] = 0;   // code: '\0'
  uint32_t code = codes.is_zero_terminated_ ? 1 : 0;
  if (codes.is_zero_terminated_) {
    if (hlens[0] == 0) return 0;
    hlens[0] -= 1;
  }

  uint32_t pos = 8 + 1 + 8;
  for (uint32_t code_length : { 2, 3, 4, 5, 6, 7, 8, 1 }) {
    const uint32_t num_codes = hlens[code_length - 1];
    printf("code-len=%d, %d codes\n", code_length, num_codes);
    if (pos + num_codes * code_length > input_size) return 0;
    for (uint32_t j = 0; j < num_codes; ++j, ++code) {
      memcpy(codes.codes_[code], input + pos, code_length);
      codes.len_[code] = code_length;
      pos += code_length;
    }
  }
  codes.num_codes_ = code;

  // robustness: complete the array
  for (; code < 255; ++code) codes.len_[code] = 0;

  codes.Print();
  assert(pos + 3 == codes.HeaderSize());
  return pos;
}

}

namespace ffsst {

bool Decompress(const std::string input, std::string& output) {
  CodeTable codes;
  const uint32_t len = input.size();
  uint32_t pos = 0;
  output.clear();
  uint32_t out_size = 0;
  uint32_t out_pos = 0;
  while (pos + 3 < len) {
    const uint32_t in_size = (((uint8_t)input[pos + 0]) << 16)
                           | (((uint8_t)input[pos + 1]) <<  8)
                           | (((uint8_t)input[pos + 2]) <<  0);
    if (in_size < 3 || pos + in_size > len) return false;
    const uint32_t c = ReadParams(&input[pos + 3], in_size - 3, codes);
    if (c == 0) return false;

    uint32_t blk_size = 0;
    for (uint32_t p = c + 3; p < in_size; ++p) {
      const uint8_t v = input[pos + p];
      if (v == 255) {
        blk_size += 1;
        p += 1;
        if (c == in_size) return false;
      } else {
        if (codes.len_[v] == 0) return false;
        blk_size += codes.len_[v];
      }
    }
    out_size += blk_size;
    output.resize(out_size);
    fprintf(stderr, "Size: in=%d out=%d (%.1f%%)\n",
            in_size, blk_size, 100. * in_size / blk_size);
    for (uint32_t p = c + 3; p < in_size; ++p) {
      const uint8_t v = (uint8_t)input[pos + p];
      assert(pos + p < input.size() && out_pos < output.size());
      if (v == 255) {
        output[out_pos] = input[pos + p + 1];
        out_pos += 1;
        p += 1;
      } else {
        const uint32_t l = codes.len_[v];
        printf("=> Code=%d (l=%d)\n", v, l);
        memcpy(&output[out_pos], &codes.codes_[v], l * sizeof(output[0]));
        out_pos += l;
      }
    }
    pos += in_size;
  }
  return true;
}

}  // namespace ffsst

//------------------------------------------------------------------------------
// utils

void CodeTable::Print() const {
  fprintf(stderr, "Num codes: %d\n", num_codes_);
  fprintf(stderr, "Is_Zero_Terminated: %d\n", is_zero_terminated_);
/*
  for (uint32_t i = 0; i < num_codes_; ++i) {
    const uint8_t* const p = (const uint8_t*)&codes_[i];
    fprintf(stderr, "code #%d (len=%d): ", i, len_[i]);
    for (uint32_t j = 0; j < len_[i]; ++j) fprintf(stderr, "0x%.2x ", p[j]);
    fprintf(stderr, "\n");
  }
*/
}
