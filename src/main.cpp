#define Py_NO_ENABLE_SHARED
#include <corecrt.h>

#include "commands.h"
#include "blue_module.h"
#include "bluecrypto.h"
//#include "buildno.h"

//#pragma comment(lib, "shared32.lib")
#pragma comment(lib, "python27.lib")
#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Cabinet.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Ole32.lib")
//#pragma comment(lib, "zlib.lib")

#include "util.h"
#include "loguru/loguru.hpp"
#include "loguru/loguru.cpp"

#include <iostream>

static std::vector<std::string> parse_all_string_args(char *argument) {
	std::vector<std::string> args;
	for (int i = 0; i < __argc; i++) {
		if (strcmp(argument, __argv[i]) == 0) {
			if (__argc >= i + 1) {
				args.push_back(std::string(__argv[i + 1]));
			}
		}
	}
	return args;
}

static bool has_argument(char *argument) {
    for (int i = 1; i < __argc; i++) {
        if (strcmp(argument, __argv[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool parse_argument(char *argument, char **value) {
	for (int i = 1; i < __argc; i++) {
		if (strcmp(argument, __argv[i]) == 0) {
			if (__argc >= i + 1) {
				*value = __argv[i + 1];
			} else {
				*value = NULL;
			}
			return true;
		}
	}

	return false;
}


#define LOG_PATH "evecc.log"

int main(int argc, char **argv) {
    loguru::add_file(LOG_PATH, loguru::Truncate, loguru::Verbosity_INFO);
    loguru::g_colorlogtostderr = false;
    if (!HasFile("C:\\Python27\\Python.exe")) {
        LOG_F(ERROR, "EVECC depends on a local Python installation.  Please install the latest version of Python 2.7 and use the default installation path of C:\\Python27\\");
        return -1;
    }
	Py_SetPythonHome("./Python");
	Py_SetProgramName(argv[0]);
	Py_Initialize();

    PySys_SetPath("./Python/Lib;./Python/Lib/site-packages;");

	LOG_F(INFO,"EVECC booting");
	LOG_F(INFO,"Initializing blue...");

	initblue();

    char *password = NULL;
    char *input_file = NULL;
    char *output_file = NULL;
    char *key_type = NULL;

    parse_argument("--password", &password);
    parse_argument("-o", &output_file);
    parse_argument("-k", &key_type);
    CryptKeyType kt = parse_key_type(key_type);


    bool is_genkey = has_argument("--gen-key");

    if (!is_genkey) {
        int status = init_cryptcontext(password);
        set_password(password);
        if (status != 0) {
            LOG_F(ERROR,"failed to initialize crypt context");
            return -1;
        }

        ctx->set_key_type = parse_key_type(key_type);
        LOG_F(INFO,"key type set to: %s", key_types[ctx->set_key_type]);
    } else {
        int status = init_cryptcontext_gen(password);
        set_password(password);

        if (status != 0) {
            LOG_F(ERROR,"failed to initialize crypt context");
            return -1;
        }
    }

    std::vector<std::string> input_files = parse_all_string_args("-I");
    if (parse_argument("--dumpcode", &input_file)) {
        return cmd_dumpcode(input_file, output_file);
    } else if (is_genkey) {
        return cmd_genkey(password);
    } else if (parse_argument("--dump-keys", &input_file)) {
        return cmd_dumpkeys(input_file);
    } else if (has_argument("--check-keys")) {
    } else if (parse_argument("--dumpcode", &input_file)) {
        return cmd_dumpcode(input_file, output_file);
    } else if (parse_argument("--compilecode", &input_file)) {
        return cmd_compilecode(input_files, output_file);
    } else if (parse_argument("--compilelib", &input_file)) {
        return cmd_compilelib(input_file, output_file);
    } else if (parse_argument("--unpyj", &input_file)) {
        cmd_unpyj(input_file, output_file);
    } else if (parse_argument("--console", &input_file)) {
        PyRun_SimpleString("import code\ncode.interact()");
    } else if (parse_argument("--script", &input_file)) {
        if (input_file == NULL) {
            LOG_F(ERROR,"input file must be supplied");
            return 0;
        }
        FILE *f = fopen(input_file, "r");
        if (f == NULL) {
            LOG_F(ERROR, "input file was not valid!");
            return 0;
        }
        PyRun_SimpleFile(f, "input_file");
        fclose(f);
    } else {
        return cmd_help();
    }

    Py_Finalize();
    return 0;
}
