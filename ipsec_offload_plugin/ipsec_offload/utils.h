// Copyright 2024-2025 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef IPSEC_PLUGIN_UTILS_H_
#define IPSEC_PLUGIN_UTILS_H_

#include <sys/stat.h>

#include <fstream>
#include <ostream>
#include <string>

// Checks to see if a path exists
inline bool PathExists(const std::string &path) {
  struct stat stbuf;
  return (stat(path.c_str(), &stbuf) >= 0);
}

// Checks to see if a path is a dir
inline bool IsDir(const std::string &path) {
  struct stat stbuf;
  if (stat(path.c_str(), &stbuf) < 0) {
    return false;
  }
  return S_ISDIR(stbuf.st_mode);
}

// Reads the contents of a file to a string buffer
int ReadFileToString(const std::string &filename, std::string *buffer);

// Parses a proto from a string
int ParseProtoFromString(const std::string &text,
                         ::google::protobuf::Message *message);

int ReadProtoFromTextFile(const std::string &filename,
                          ::google::protobuf::Message *message);

#endif // IPSEC_PLUGIN_UTILS_H_