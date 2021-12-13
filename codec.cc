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
// Author: Skal (pascal.massimino@gmail.com)

#include "ffsst.h"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <sstream>

//------------------------------------------------------------------------------
namespace {
std::string ReadFile(const char name[]) {
  std::ifstream in(name);
  std::stringstream sstr;
  sstr << in.rdbuf();
  return sstr.str();
}

bool WriteFile(const std::string& bytes, const char name[]) {
  std::ofstream fout(name);
  fout << bytes;
  fout.close();
  return fout.good();
}
}  // anonymous namespace
//------------------------------------------------------------------------------

const int kMaxEffort = 4;

int main(int argc, const char* argv[]) {
  const char* in_name = nullptr;
  const char* out_name = nullptr;
  bool decompress = false;
  bool check = false;
  bool verbose = false;
  int effort = 4;

  for (int c = 1; c < argc; ++c) {
    if (!strcmp(argv[c], "-h")) {
      printf("Usage: %s in_file [-o outfile] [options]\n", argv[0]);
      printf("options:\n");
      printf(" -effort <int> ... compression effort (in [0..2])\n");
      printf(" -d .............. decompress in_file\n");
      printf(" -check .......... verify after compression\n");      
      printf(" -v .............. verbose\n");
      printf(" -h .............. this help\n");
      return 0;
    } else if (!strcmp(argv[c], "-o") && c + 1 < argc) {
      out_name = argv[++c];
    } else if (!strcmp(argv[c], "-d")) {
      decompress = true;
    } else if (!strcmp(argv[c], "-check")) {
      check = true;
    } else if (!strcmp(argv[c], "-effort") && c + 1 < argc) {
      effort = atoi(argv[++c]);
      effort = (effort < 0) ? 0 : (effort > kMaxEffort) ? kMaxEffort : effort;
    } else if (!strcmp(argv[c], "-v")) {
      verbose = true;
    } else {
      in_name = argv[c];
    }
  }
  if (in_name == nullptr) {
    fprintf(stderr, "Missing input name! Try -h for help.\n");
    return 1;
  }
  const std::string in = ReadFile(in_name);
  printf("input : %lu bytes\n", in.size());

  std::string out;
  const bool ok = decompress ? ffsst::Decompress(in, out)
                             : ffsst::Compress(in, out, effort, verbose);
  if (!ok) {
    fprintf(stderr, "Error during processing!\n");
    return 1;
  }
  printf("==== Output : %lu bytes (comp ratio = %.2lf) ====\n",
         out.size(), 1. * in.size() / out.size());

  if (out_name != nullptr) {
    if (!WriteFile(out, out_name)) return 1;
    printf("Saved file '%s'.\n", out_name);
  }

  if (check && !decompress) {
    std::string verif;
    if (!ffsst::Decompress(out, verif) || verif != in) {
      fprintf(stderr, "Verification failed!\n");
      return 1;
    } else {
      printf("Verification OK.\n");
    }
  }
  return 0;
}
