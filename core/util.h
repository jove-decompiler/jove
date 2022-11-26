#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace jove {

void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
std::string read_file_into_string(char const *infile);
long robust_read(int fd, void *const buf, const size_t count);
long robust_write(int fd, const void *const buf, const size_t count);
long size_of_file32(const char *path);
long robust_sendfile(int socket, const char *file_path, size_t file_size);
long robust_sendfile_with_size(int socket, const char *file_path);
long robust_receive_file_with_size(int socket, const char *out, unsigned file_perm);
unsigned num_cpus(void);
void IgnoreCtrlC(void);

}
