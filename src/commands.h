//
// Created by nick on 2/5/2023.
//

#ifndef EVECC_COMMANDS_H
#define EVECC_COMMANDS_H

#include <vector>
#include <string>
#include "bluecrypto.h"
#include "loguru/loguru.hpp"
#include <chrono>

#ifdef _DEBUG
#undef _DEBUG
#include <Python.h>
#define _DEBUG
#endif


#define RSA_PUB "\x06\x02\x00\x00\x00\x24\x00\x00\x52\x53\x41\x31"
#define RSA_LEN 0x94
#define TDES_SIG "\x01\x02\x00\x00\x03\x66\x00\x00\x00\xA4\x00\x00"
#define TDES_LEN 0x8C

int cmd_dumpcode(char *input_file, char *output_file);
int cmd_dumplib(char *input_file, char *output_file);
int cmd_compilecode(std::vector<std::string> input_files, char *output_file);
int cmd_unpyj(char *input_file, char *output_file);
int cmd_compilelib(char *input_file, char *output_file);
int cmd_help();
int cmd_genkey(char *password);
int cmd_dumpkeys(char *file);

#endif //EVECC_COMMANDS_H
