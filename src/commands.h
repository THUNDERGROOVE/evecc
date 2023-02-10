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

#define RSA_PUB "\x06\x02\x00\x00\x00\x24\x00\x00\x52\x53\x41\x31"
#define RSA_LEN 0x94
#define TDES_SIG "\x01\x02\x00\x00\x03\x66\x00\x00\x00\xA4\x00\x00"
#define TDES_LEN 0x8C

struct cmd_args {
    char *password;
    char *input_file;
    char *output_file;
    char *key_type;

    std::vector<std::string> input_files;

    bool do_cleancache;
    bool do_nocache;
    bool do_genkeys;
    bool do_dumpcode;
    bool do_dumplib;
    bool do_compilecode;
    bool do_unpyj;
    bool do_compilelib;
    bool do_help;
    bool do_runscript;
    bool do_console;
    bool do_dumpkeys;
    cmd_args() {
        memset(this, 0, sizeof(*this));
    }
};

int cmd_dumpcode(cmd_args *args);
int cmd_dumplib(cmd_args *args);
int cmd_compilecode(cmd_args *args);
int cmd_unpyj(cmd_args *args);
int cmd_compilelib(cmd_args *args);
int cmd_help();
int cmd_genkey(cmd_args *args);
int cmd_dumpkeys(cmd_args *args);

#endif //EVECC_COMMANDS_H
