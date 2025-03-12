// Copyright 2024 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#include <google/protobuf/message.h>
#include <google/protobuf/text_format.h>

#include "utils.h"
#include "log_plugin.h"

int ReadFileToString(const std::string& filename,
                     std::string* buffer) {
  if (!PathExists(filename)) {
    LOGGER->Log("ERROR: %s: Failed to open file: %s",
		    __func__, filename.c_str());
    return -1;
  }
  if (IsDir(filename)) {
    LOGGER->Log("ERROR: %s: %s is a directory!",
		    __func__, filename.c_str());
    return -1;
  }

  std::ifstream infile;
  infile.open(filename.c_str());
  if (!infile.is_open()) {
    LOGGER->Log("ERROR: %s when opening file %s",
		    __func__, filename.c_str());
    return -1;
  }

  std::string contents((std::istreambuf_iterator<char>(infile)),
                       (std::istreambuf_iterator<char>()));
  buffer->append(contents);
  infile.close();

  return 0;
}

int ParseProtoFromString(const std::string& text,
                        ::google::protobuf::Message* message) {
  if (!::google::protobuf::TextFormat::ParseFromString(text, message)) {
    LOGGER->Log("ERROR: %s Failed to parse proto from following string: %s",
		    __func__, text.c_str());
    return -1;
  }

  return 0;
}

int ReadProtoFromTextFile(const std::string& filename,
                         ::google::protobuf::Message* message) {
  std::string text;
  auto status = ReadFileToString(filename, &text);
  if(status != 0) 
    return status;
  
  status = ParseProtoFromString(text, message);
  return status;
}
