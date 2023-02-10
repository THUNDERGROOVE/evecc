#define Py_NO_ENABLE_SHARED
#include <corecrt.h>
#include <iostream>

#include "commands.h"
#include "blue_module.h"
#include "bluecrypto.h"
#include "util.h"
#include "loguru/loguru.hpp"
#include "loguru/loguru.cpp"


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

static bool has_argument(char *argument, int place) {
    if (place < 0) {
        for (int i = 1; i < __argc; i++) {
            if (strcmp(argument, __argv[i]) == 0) {
                return true;
            }
        }
    } else {
        if (place < __argc && strcmp(argument, __argv[place]) == 0) {
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
    if (!HasFile("./Python/Lib") || !HasFile("./Python/uncompyle2.zip")) {
        LOG_F(ERROR, "EVECC depends on a local Python scripts which are missing.");
        return -1;
    }
	Py_SetPythonHome("./Python");
	Py_SetProgramName(argv[0]);
	Py_Initialize();
    PySys_SetPath("./Python/Lib;./Python/uncompyle2.zip;");

	LOG_F(INFO,"EVECC booting");
	LOG_F(INFO,"Initializing blue...");

	initblue();

    cmd_args *args = new cmd_args();

    args->do_dumpcode = has_argument("dumpcode", 1);
    args->do_dumplib = has_argument("dumplib", 1);
    args->do_compilecode = has_argument("compilecode", 1);
    args->do_compilelib = has_argument("compilelib", 1);
    args->do_dumpkeys = has_argument("dumpkeys", 1);
    args->do_genkeys = has_argument("genkeys", 1);
    args->do_help = has_argument("help", 1) || has_argument("--help", -1) || has_argument("-h", -1);
    args->do_unpyj = has_argument("unpyj", 1);
    args->do_console = has_argument("console", 1);
    args->do_runscript = has_argument("runscript", 1);

    parse_argument("-i", &args->input_file);
    parse_argument("-o", &args->output_file);
    parse_argument("--password", &args->password);
    parse_argument("-k", &args->key_type);
    args->input_files = parse_all_string_args("-I");


    CryptKeyType kt = parse_key_type(args->key_type);

    if (args->do_help) {
        return cmd_help();
    }

    if (args->do_dumpcode || args->do_runscript ||
        args->do_console || args->do_unpyj ||
        args->do_compilelib || args->do_compilecode || args->do_dumplib) {
        LOG_F(INFO, "initializing crypto context");

        int status = init_cryptcontext(args->password);
        set_password(args->password);
        if (status != 0) {
            LOG_F(ERROR,"failed to initialize crypt context");
            return -1;
        }

        ctx->set_key_type = kt;
        LOG_F(INFO,"key type set to: %s", key_types[ctx->set_key_type]);
    }
    if (args->do_genkeys || args->do_dumpkeys){
        int status = init_cryptcontext_gen(args->password);
        set_password(args->password);

        if (status != 0) {
            LOG_F(ERROR,"failed to initialize crypt context");
            return -1;
        }
    }

    if (args->do_dumpcode) {
        return cmd_dumpcode(args);
    } else if (args->do_genkeys) {
        return cmd_genkey(args);
    } else if (args->do_dumplib) {
        return cmd_dumplib(args);
    } else if (args->do_dumpkeys) {
        return cmd_dumpkeys(args);
    } else if (args->do_dumpcode) {
        return cmd_dumpcode(args);
    } else if (args->do_compilecode) {
        return cmd_compilecode(args);
    } else if (args->do_compilelib) {
        return cmd_compilelib(args);
    } else if (args->do_unpyj) {
        cmd_unpyj(args);
    } else if (args->do_console) {
        PyRun_SimpleString("import code\ncode.interact()");
    } else if (args->do_runscript) {
        if (args->input_file == NULL) {
            LOG_F(ERROR,"-i <input> file must be supplied");
            return 0;
        }
        FILE *f = fopen(args->input_file, "r");
        if (f == NULL) {
            LOG_F(ERROR, "input file (%v) was not valid!", args->input_file);
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
