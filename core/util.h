#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace jove {

void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
std::string read_file_into_string(char const *infile);
long size_of_file32(const char *path);
unsigned num_cpus(void);
void IgnoreCtrlC(void);

}
