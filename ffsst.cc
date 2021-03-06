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
#include <queue>

using std::vector;

namespace {

const uint32_t NoMatch = ~0u;

const uint8_t kVersionString[8] = {
  0x01 /*endian marker*/,
  0xff /*nSymbols*/,
  0x01 /*terminator*/,
  0x00 /*suffixLim*/,
  0x0a, 0x14, 0x34, 0x01
};

struct Code {
  uint8_t code_[8] = { 0 };
  uint8_t len_ = 0;
  uint32_t freq_ = 0;
  uint32_t rank_;
  uint32_t id_;

  // for debug
  uint64_t code() const { return *(uint64_t*)code_; }  // endianess!

  static bool IdSort(const Code& a, const Code& b) { return (a.id_ < b.id_); }
  uint32_t score() const { return (len_ + 5) * freq_; }
  bool operator<(const Code& other) const {
    const uint32_t s0 = score(), s1 = other.score();
    if (s0 != s1) return (s0 > s1);
    return (rank_ < other.rank_);
  }
  void Print() const { printf("0x%16llx (l=%d freq=%d)", code(), len_, freq_); }
};

struct CodeTable {
  vector<Code> codes_;
  bool is_zero_terminated_ = false;

 public:
  void Clear() {
    codes_.clear();
    is_zero_terminated_ = false;
  }

  bool WriteMsg(const std::string& msg, std::string& output);
  // insert the first 255 codes[] (at most) in the table. Non-visible
  // codes with freq_ == 0 are ignored.
  void Insert(const Code codes[], uint32_t size);
  void CollectSingletons(const uint8_t* msg, uint32_t msg_len);
  void Optimize(const uint8_t* msg, uint32_t msg_len, bool verbose);
};

//------------------------------------------------------------------------------
// encoding

const size_t kMaxBlkSize = 1u << 22;

struct Indexer {
  uint8_t num_[256];     // number of sequences starting with 'idx'
  uint8_t pos_[256];     // where the sequence starts
  uint8_t seq_[256];     // the sequence
  const CodeTable& tbl_;

  Indexer(const CodeTable& tbl) : tbl_(tbl) {
    memset(num_, 0, sizeof(num_));
    for (const auto& C : tbl.codes_) ++num_[C.code_[0]];
    uint8_t p = 0;
    for (uint32_t c = 0; c < 256; ++c) {
      pos_[c] = p;
      p += num_[c];
    }
    uint8_t pos[256];
    memcpy(pos, pos_, sizeof(pos));
    for (const auto& C : tbl.codes_) {
      const uint8_t idx = C.code_[0];
      seq_[pos[idx]++] = (&C - tbl.codes_.data());
    }
  }
  uint32_t Match(const uint8_t input[], uint32_t max_len) const {
    const uint8_t idx = input[0];
    const uint8_t num = num_[idx];
    const uint8_t* seq = &seq_[pos_[idx]];
    uint32_t best_len = 0;
    uint32_t best_code = NoMatch;
    for (uint32_t p = 0; p < num; ++p) {
      const uint32_t c = seq[p];
      const uint32_t len = tbl_.codes_[c].len_;
      if (len <= max_len && len > best_len) {
        if (!memcmp(input, tbl_.codes_[c].code_, len)) {
          best_len = len;
          best_code = c;
        }
      }
    }
    return best_code;
  }
  void Matches(const uint8_t input[], uint32_t max_len,
               uint32_t codes[8]) const {
    const uint8_t idx = input[0];
    const uint8_t num = num_[idx];
    const uint8_t* seq = &seq_[pos_[idx]];
    for (uint8_t p = 0; p < 8; ++p) codes[p] = NoMatch;
    for (uint32_t p = 0; p < num; ++p) {
      const uint32_t c = seq[p];
      const uint32_t len = tbl_.codes_[c].len_;
      if (len <= max_len && codes[len - 1] == NoMatch &&
          !memcmp(input, tbl_.codes_[c].code_, len)) {
        codes[len - 1] = c;
      }
    }
  }
  uint32_t LengthOf(const uint32_t code) const {
    return tbl_.codes_[code].len_;
  }
};


struct Stats {
  // process msg[] with the current table and record occurrences
  // of codes and pairs of codes.
  void Collect(const Indexer& idx, const uint8_t* msg, uint32_t len) {
    Clear();
    for (uint32_t i = 0; i < len;) {
      const uint32_t max_len = std::min(len - i, 8u);
      const uint32_t code0 = idx.Match(msg + i, max_len);
      if (code0 != NoMatch) {
        ++cnt1[code0];
        const uint32_t l = idx.LengthOf(code0);
        const uint32_t j = std::min(i + l, len);
        assert(l > 0);
        const uint32_t max_len = std::min(len - j, 8u - l);
        const uint32_t code1 = idx.Match((const uint8_t*)&msg[j], max_len);
        if (code1 != NoMatch) ++cnt2[code0][code1];
        i = j;
      } else {
        i += 1;
      }
    }
  }
  void Clear() {
    memset(cnt1, 0, sizeof(cnt1));
    memset(cnt2, 0, sizeof(cnt2));
  }
  static Code Merge(const Code& code1, const Code& code2) {
    Code c = code1;
    assert(c.len_ + code2.len_ <= 8u);
    for (uint32_t i = 0; i < code2.len_; ++i) c.code_[c.len_ + i] = code2.code_[i];
    c.len_ += code2.len_;
    assert(c.len_ <= 8u);
    return c;
  }
  void Print() {
    for (uint32_t i = 0; i < 256; ++i) {
      if (cnt1[i]) {
        printf("#%d: cnt=%d\n", i, cnt1[i]);
        for (uint32_t j = 0; j < 256; ++j) {
          if (cnt2[i][j]) {
            printf("  =>%d: cnt2=%d\n", j, cnt2[i][j]);
          }
        }
      }
    }
  }

  static const uint32_t kMax = 255;
  template<typename T> static void Update(T& q, Code c) {
    if (q.size() == kMax || (!q.empty() && q.top().score() < c.score())) {
      q.pop();
    }
    q.push(c);
  }
  void Extract(CodeTable& table, bool verbose) {
    auto cmp = [](const Code& a, const Code& b) {
      return (a.score() > b.score());
    };
    std::priority_queue<Code, vector<Code>, decltype(cmp)> qm(cmp);
    const uint32_t num_codes = table.codes_.size();
    for (uint32_t i = 0; i < num_codes; ++i) {
      if (cnt1[i]) {
        Code code1 = table.codes_[i];
        code1.freq_ = cnt1[i];
        code1.rank_ = i;
        Update(qm, code1);
        for (uint32_t j = 0; j < num_codes; ++j) {
          if (cnt2[i][j]) {
            Code c = Merge(code1, table.codes_[j]);
            c.freq_ = cnt2[i][j];
            c.rank_ = j;
            Update(qm, c);
          }
        }
      }
    }
    Code codes[kMax];
    uint32_t num = 0;
    while (!qm.empty()) {
      codes[num] = qm.top();
      qm.pop();
      if (verbose) {
        printf("%d: ", num);
        codes[num].Print();
        printf("\n");
      }
      ++num;
    }
    table.Clear();
    table.Insert(codes, num);
  }

 public:
  uint32_t cnt1[256];  // count of code frequency
  uint32_t cnt2[256][256];  // frequency of code pairs
};

bool CodeTable::WriteMsg(const std::string& msg, std::string& output) {
  bool used[255] = { false };
  for (uint32_t p = 0; p < msg.size(); ++p) {
    const uint8_t code = (uint8_t)msg[p];
    if (code == 255u) {
      ++p;
    } else {
      used[code] = true;
    }
  }

  uint32_t num_used = 0;
  Code new_codes[255];
  uint8_t hlens[8] = { 0 };
  for (uint32_t i = 0; i < 255; ++i) {
    if (used[i]) {
      auto &c = new_codes[num_used++];
      c = codes_[i];
      c.rank_ = i;
      const uint32_t l = c.len_;
      c.id_ = (hlens[l - 1]++) + (((l - 2) & 7) << 8);
    }
  }
  std::sort(new_codes, new_codes + num_used, Code::IdSort);

  uint8_t map[256];
  size_t hdr_size = 0;
  char hdr[255 * 8];
  for (uint32_t i = 0; i < num_used; ++i) {
    map[new_codes[i].rank_] = i;
    const auto& c = new_codes[i];
    memcpy(hdr + hdr_size, c.code_, c.len_);
    hdr_size += c.len_;
  }
  map[255] = 255;

  printf("code-len: ");
  for (const auto& l : hlens) printf("[%d]", l);
  printf("\nnum used: %u header size:%u\n", num_used, (uint32_t)hdr_size);

  const size_t size = 3 + 8 + 1 + 8 + hdr_size + msg.size();
  if (size >= (1u << 24)) return false;
  char tmp[3 + 8 + 1] = { 0 };
  tmp[0] = (size >> 16) & 0xff;
  tmp[1] = (size >>  8) & 0xff;
  tmp[2] = (size >>  0) & 0xff;
  memcpy(tmp + 3, kVersionString, 8 * sizeof(kVersionString[0]));
  if (is_zero_terminated_) tmp[3 + 8] |= 1;
  output.append(tmp, sizeof(tmp));
  output.append((const char*)hlens, 8);
  output.append(hdr, hdr_size);

  // remap code to final values
  size_t s = output.size();
  printf("Output size: %u -> %u\n", (uint32_t)s, (uint32_t)size);
  output += msg;
  while (s < output.size()) {
    const uint8_t c = (uint8_t)output[s];
    output[s++] = map[c];
    if (c == 255u) ++s;
  }
  return true;
}

//------------------------------------------------------------------------------
// Analysis

void CodeTable::Insert(const Code codes[], uint32_t size) {
  codes_.clear();
  // least used codes will be escaped if needed.
  // Assumes codes[] is sorted by decreasing freq_
  for (uint32_t i = 0; i < size && codes[i].freq_ != 0; ++i) {
    codes_.push_back(codes[i]);
    if (codes_.size() == 255u) break;
  }
}

void CodeTable::CollectSingletons(const uint8_t* msg, uint32_t msg_len) {
  codes_.resize(256);
  for (uint32_t i = 0; i < msg_len; ++i) ++codes_[msg[i]].freq_;

  uint32_t num_codes = 0;
  for (uint32_t i = 0; i < 256; ++i) {
    if (codes_[i].freq_ != 0) {
      auto& c = codes_[num_codes];
      c = codes_[i];
      c.code_[0] = i;
      c.len_ = 1;
      c.rank_ = num_codes;
      ++num_codes;
    }
  }
  codes_.resize(num_codes);
}

void CodeTable::Optimize(const uint8_t* msg, uint32_t msg_len, bool verbose) {
  for (uint32_t N = 0; N <= 2; ++N) {
    Stats stats;
    Indexer idx(*this);
    stats.Collect(idx, msg, msg_len);
    stats.Extract(*this, verbose);
    if (verbose) printf("OK stage #%d!\n", N);
  }
}

bool Analyze(const uint8_t* msg, uint32_t msg_len, CodeTable& table,
             int effort, bool verbose) {
  if (effort == 0) return true;
  if (effort == 1) {
    table.CollectSingletons(msg, msg_len);
  } else if (effort == 4) {
    table.CollectSingletons(msg, msg_len);
    table.Optimize(msg, msg_len, verbose);
  } else if (effort == 2 || effort == 3) {
    std::map<std::string, uint32_t> counts;
    for (uint32_t i = 0; i < msg_len; ++i) {
      for (uint32_t j = 1; j <= 8; ++j) {
        if (i + j > msg_len) break;
        const std::string str((const char*)msg + i, j);
        ++counts[str];
      }
    }
    if (verbose) {
      printf("counts: size=%u / %u\n",
             (uint32_t)counts.size(), (uint32_t)msg_len);
    }
    vector<Code> codes(counts.size());
    uint32_t i = 0;
    for (auto it = counts.begin(); it != counts.end(); ++it) {
      auto& C = codes[i];
      C.rank_ = i;
      C.freq_ = it->second;
      C.len_ = it->first.size();
      memcpy(C.code_, it->first.data(), C.len_);
      ++i;
    }
    std::sort(codes.begin(), codes.end());
    table.Insert(codes.data(), codes.size());
    if (effort == 3) table.Optimize(msg, msg_len, verbose);
  } else {
    printf("Effort %d : NYI.\n", effort);
  }
  return true;
}

//------------------------------------------------------------------------------
// tmp buffer size.
static const size_t kMaxBuf = 8192;

// basic escape coding
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
  return output.size();
}

// greedy coding
uint32_t CodeBlk1(const uint8_t* input, uint32_t in_len, CodeTable& codes,
                  std::string& output) {
  size_t pos = 0;
  char tmp[kMaxBuf + 1];
  Indexer idx(codes);
  for (uint32_t p = 0; p < in_len; ) {
    const uint32_t code = idx.Match(input + p, std::min(in_len - p, 8u));
    if (code == NoMatch) {
      tmp[pos++] = 255u;
      tmp[pos++] = input[p++];
    } else {
      tmp[pos++] = code;
      p += codes.codes_[code].len_;
    }
    if (pos >= kMaxBuf) {
      output.append(tmp, pos);
      pos = 0;
    }
  }
  if (pos > 0) output.append(tmp, pos);
  return output.size();
}

// Shortest path algorithm
uint32_t CodeBlk2(const uint8_t* input, uint32_t in_len, CodeTable& codes,
                  std::string& output) {
  Indexer idx(codes);

  struct Node {
    uint32_t code;        // code to use to go to the previous node
    uint32_t len = ~0u;   // number of nodes in the previous best chain
  };
  vector<Node> nodes(in_len + 1);
  nodes[0].len = 0;

  for (uint32_t p = 0; p < in_len; ++p) {
    const uint8_t max_len = std::min(in_len - p, 8u);
    // retrieve all possible matches
    uint32_t matches[8];
    idx.Matches(input + p, max_len, matches);
    const Node& src = nodes[p];
    for (uint32_t l = 1; l <= max_len; ++l) {
      const uint32_t code = matches[l - 1];
      if (code != NoMatch || l == 1) {
        Node& dst = nodes[p + l];
        const uint32_t len = src.len + (code == NoMatch ? 2 : 1);
        if (len < dst.len) {  // minimize length
          dst.len = len;
          dst.code = code;
        }
      }
    }
  }
  printf("Best final len:   %u\n", nodes[in_len].len);

  uint32_t pos = output.size() + nodes[in_len].len;
  output.resize(pos);
  for (uint32_t p = in_len; p > 0; ) {
    const uint32_t code = nodes[p].code;
    if (code == NoMatch) {
      output[--pos] = input[--p];
      output[--pos] = 255u;
    } else {
      p -= codes.codes_[code].len_;
      output[--pos] = code;
    }
  }
  return output.size();
}

}  // namespace

//------------------------------------------------------------------------------

namespace ffsst {

bool Compress(const std::string input, std::string& output,
              int effort, bool verbose) {
  output.clear();
  uint32_t in_pos = 0;
  while (in_pos < input.size()) {
    const size_t blk_size = std::min(input.size() - in_pos, kMaxBlkSize);
    const uint8_t* const src = (const uint8_t*)&input[in_pos];

    CodeTable codes;
    if (effort > 0 &&
        !Analyze(src, blk_size, codes, effort, verbose)) {
      return false;
    }

    std::string msg;
    size_t msg_size =
        (effort == 0) ? CodeBlk0(src, blk_size, codes, msg) :
        (effort == 1) ? CodeBlk1(src, blk_size, codes, msg) :
                        CodeBlk2(src, blk_size, codes, msg);
    if (!codes.WriteMsg(msg, output)) {
      fprintf(stderr, "Bad WriteParams()!\n");
      return false;
    }
    in_pos += blk_size;
  }
  return true;
}

}  // namespace ffsst

//------------------------------------------------------------------------------
