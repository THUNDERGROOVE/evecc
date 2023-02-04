//#define Py_NO_ENABLE_SHARED
#include <corecrt.h>

#ifdef _DEBUG
#undef _DEBUG
#include <Python.h>
#define _DEBUG

int cmd_genkey();

#endif
#include <vector>

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

#include "scripts.h"

#include <iostream>
#include <chrono>
using namespace std::chrono;

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

static int cmd_dumpcode(char *input_file, char *output_file) {
	// @TODO: This
	return 0;
}

static int cmd_dumplib(char *input_file, char *output_file) {
	// @TODO: This
	return 0;
}

static int cmd_compilecode(std::vector<std::string> input_files,
			   char *output_file) {
	high_resolution_clock::time_point t1 = high_resolution_clock::now();
	PyGILState_STATE s = PyGILState_Ensure();
	PyObject *main = PyImport_AddModule("__main__");

	if (input_files.size() > 0) {
		//PyObject *p = PyString_FromString(input_file);
		//PyObject_SetAttrString(main, "input_path", p);
		//Py_DECREF(p);
		PyObject *p = PyList_New(input_files.size());
		for (uint32_t i = 0; i < input_files.size(); i++) {
			PyObject *str =
				PyString_FromString(input_files[i].c_str());
			//PyList_Append(p, str);
			PyList_SetItem(p, i, str);
			//Py_DECREF(str);
		}
		PyObject_SetAttrString(main, "input_paths", p);
		//Py_DECREF(p);
	} else {
		printf("No input paths set. (Use -I flag)\n");
		return 3;
	}

	if (output_file != NULL) {
		PyObject *o = PyString_FromString(output_file);
		PyObject_SetAttrString(main, "output_path", o);
		//Py_DECREF(o);
	}

	//Py_DECREF(main);

	int r = PyRun_SimpleString(compile_code_script);

	PyGILState_Release(s);

	high_resolution_clock::time_point t2 = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(t2 - t1).count();
	std::cout << "Compiled codefile in " << duration << "us\n";
	fflush(stdout);
	return r;
}

static int cmd_unpyj(char *input_file, char *output_file) {
	FILE *f = fopen(input_file, "rb");
	if (f == NULL) {
		printf("cmd_unpyj: unable to open input file\n");
		return -1;
	}

	fseek(f, 0, SEEK_END);
	uint32_t size = ftell(f);
	rewind(f);

	char *data = (char *)calloc(1, size);
	fread(data, 1, size, f);
	fclose(f);

	char *out = (char *)calloc(1, size * 2);
	uint32_t os = UnjumbleString(data, size, out, size * 2, ctx->set_key_type);
	f = fopen(output_file, "wb");
	fwrite(out, os, 1, f);
	fclose(f);
	return 0;
}

static int cmd_compilelib(char *input_file, char *output_file) {
	high_resolution_clock::time_point t1 = high_resolution_clock::now();
	PyGILState_STATE s = PyGILState_Ensure();
	PyObject *main = PyImport_AddModule("__main__");

	if (input_file != NULL) {
		PyObject *p = PyString_FromString(input_file);
		PyObject_SetAttrString(main, "input_path", p);
		Py_DECREF(p);
	}

	if (output_file != NULL) {
		PyObject *o = PyString_FromString(output_file);
		PyObject_SetAttrString(main, "output_path", o);
		//Py_DECREF(o);
	}
	int r = PyRun_SimpleString(compile_lib_script);

	PyGILState_Release(s);

	high_resolution_clock::time_point t2 = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(t2 - t1).count();
	std::cout << "Compiled lib in " << duration << "us\n";
	return r;
}

static int cmd_help() {
	printf("%s(%s): Compile shit for EVE\n", __argv[0], "it's-fucked");//BUILD_NO);
	printf("    --dumpcode <codefile> <output directory>\n");
	printf("    --dumplib <libfile> -i <output directory>\n");
	printf("    --compilecode -o <output file> <-I ...>\n");
	printf("    --compilelib <code lib> -o <output file>\n");
    printf("    --gen-key \n");

	return 0;
}

int cmd_genkey(char *password) {
    if (password == NULL) {
//        printf("--gen-key requires the use of --password <password>\n");
//        return -1;
    }

    printf(" >> making code accessors\n");
    if (make_code_accessors(password)) {
        printf("yay, it worked!");
    }

    return 0;
}

CryptKeyType parse_key_type(char *type) {
    if (type == NULL) {
        return CRYPTKEY_ROAMING;
    }
    int i = 0;
    while (true) {
        if (key_types[i] == NULL) {
            break;
        }
        if (strcmp(key_types[i], type) == 0) {
            return (CryptKeyType)i;
        }
        i++;
    }
    return CRYPTKEY_ROAMING;
}


int main(int argc, char **argv) {
	Py_SetPythonHome("C:\\Python27\\");
	Py_SetProgramName(argv[0]);
	Py_Initialize();

	printf(" >> EVECC booting\n");
	printf(" >> Initializing blue...\n");

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

    if (kt != CRYPTKEY_NO_CRYPTO) {
        if (!is_genkey) {
            int status = init_cryptcontext(password);
            set_password(password);
            if (status != 0) {
                printf(" >>> failed to initialize crypt context\n");
                return -1;
            }

            ctx->set_key_type = parse_key_type(key_type);
            printf(" >> key type set to: %s\n", key_types[ctx->set_key_type]);
        } else {
            int status = init_cryptcontext_gen(password);
            set_password(password);

            if (status != 0) {
                printf(" >>> failed to initialize crypt context\n");
                return -1;
            }
        }
    } else {
        ctx = new CryptContext;
        ctx->set_key_type = kt;
        set_password(password);
    }

	std::vector<std::string> input_files = parse_all_string_args("-I");
	if (parse_argument("--dumpcode", &input_file)) {
        return cmd_dumpcode(input_file, output_file);
    } else if (is_genkey) {
        return cmd_genkey(password);
    } else if (has_argument("--check-keys")) {
	} else if (parse_argument("--dumplib", &input_file)) {
		return cmd_dumplib(input_file, output_file);
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
			printf("input file must be supplied\n");
			return 0;
		}
		FILE *f = fopen(input_file, "r");
		if (f == NULL) {
			printf("input file was not valid!\n");
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
