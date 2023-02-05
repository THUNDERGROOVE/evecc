//
// Created by nick on 2/5/2023.
//

#include <iostream>
#include "commands.h"
#include "util.h"

#include "scripts.h"

using namespace std::chrono;

int cmd_dumpcode(char *input_file, char *output_file) {
    // @TODO: This
    return 0;
}


int cmd_dumplib(char *input_file, char *output_file) {
    // @TODO: This
    return 0;
}

int cmd_compilecode(std::vector<std::string> input_files,
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
		LOG_F(ERROR,"No input paths set. (Use -I flag)");
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

int cmd_unpyj(char *input_file, char *output_file) {
	FILE *f = fopen(input_file, "rb");
	if (f == NULL) {
		LOG_F(ERROR,"cmd_unpyj: unable to open input file");
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

int cmd_compilelib(char *input_file, char *output_file) {
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

int cmd_help() {
	printf("%s(%s): Compile shit for EVE\n", __argv[0], "it's-fucked");//BUILD_NO);
	printf("    --dumpcode <codefile> <output directory>\n");
	printf("    --dumplib <libfile> -i <output directory>\n");
	printf("    --compilecode -o <output file> <-I ...>\n");
	printf("    --compilelib <code lib> -o <output file>\n");
    printf("    --gen-key \n");

	return 0;
}

int cmd_genkey(char *password) {
    LOG_F(INFO,"making code accessors");

    if (make_code_accessors(password)) {
        LOG_F(INFO,"code accessors generated sucessfully");
    }

    return 0;
}

int cmd_dumpkeys(char *file) {
    FILE *f = fopen(file, "rb");
    if (f == NULL) {
        LOG_F(ERROR,"could not open input file: %s", file);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(size);
    char *rewind = buf;
    fread(buf, sizeof(char), size, f);
    fclose(f);


    keys_blob *keys = new keys_blob;
    keys->pub_key = (char *)calloc(RSA_LEN, sizeof(char));
    keys->crypt_blob  = (char *)calloc(TDES_LEN, sizeof(char));

    LOG_F(INFO,"scanning for RSA public key");
    char *ptr = (char *)memmem(buf, size, RSA_PUB, sizeof(RSA_PUB));
    if (ptr == NULL) {
        LOG_F(ERROR,"could not find RSA_PUB in input file: %s", file);
        return -2;
    }
    buf = rewind;
    LOG_F(INFO, "RSA public key found!");
    memcpy(keys->pub_key, ptr, RSA_LEN);
    keys->pub_key_size = RSA_LEN;

    LOG_F(INFO,"scanning for 3DES crypt key");
    ptr = (char *)memmem(buf, size, TDES_SIG, sizeof(TDES_SIG)-2);
    if (ptr == NULL) {
        LOG_F(INFO," could not find TDES_SIG in input file: %s", file);
        return -3;
    }
    LOG_F(INFO, "3DES crypt key found!");
    memcpy(keys->crypt_blob, ptr, TDES_LEN);
    keys->crypt_blob_size = TDES_LEN;

    keys->dump(CCP_KEYS);
    return 0;
}
