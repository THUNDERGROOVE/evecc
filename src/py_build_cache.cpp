//
// Created by nick on 2/10/2023.
//

#include "py_build_cache.h"
#include "loguru/loguru.hpp"
#include <Windows.h>

bool DO_BUILD_CACHING = true;

int32_t get_build_hash() {
    std::string args("");
    for (int i = 0; i < __argc; i++) {
        args.append(__argv[i]);
        args.append(" ");
	}
    return crc32c::Crc32c(args);
}

#include <filesystem>
namespace fs = std::filesystem;

void set_do_build_cache(bool do_cache) {
    DO_BUILD_CACHING = do_cache;
}

char *get_cache(int32_t *data_size, std::string filename) {
    if (!DO_BUILD_CACHING) {
        return NULL;
    }
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    int32_t hash = get_build_hash();
    sprintf(buf, "%d", hash);
    std::string cache_path(".build_cache");
    cache_path.append("/");
    cache_path.append(buf);
    cache_path.append("/");
    std::string cln = filename;
    cln.erase(cln.begin(), cln.begin()+3);
    cache_path.append(cln);

    fs::path real_file(filename);
    fs::path cache_file(cache_path);
    if (!fs::exists(cache_path)) {
        return NULL;
    }
    if (fs::last_write_time(real_file) > fs::last_write_time(cache_file)) {
        LOG_F(MAX, "while getting cache cache for %s, py file is newer.", cache_path.c_str());
        fs::remove(cache_file);
        return NULL;
    }

    FILE *f = fopen(cache_path.c_str(), "rb");
    if (f == NULL) {
        LOG_F(ERROR, "failed to open build cache file %s", cache_path.c_str());
        exit(-1);
    }
    fseek(f, 0, SEEK_END);
    int len = ftell(f);
    rewind(f);
    char *out = (char *)malloc(len);
    fread(out, 1, len, f);
    fclose(f);
    *data_size = len;
    LOG_F(MAX, "got log cache for %s", cache_path.c_str());
    return out;
}

void install_cache(std::string filename, char *data, int32_t data_size) {
    if (!DO_BUILD_CACHING) {
        return;
    }
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    int32_t hash = get_build_hash();
    sprintf(buf, "%d", hash);
    std::string cache_path(".build_cache");
    cache_path.append("/");
    cache_path.append(buf);
    cache_path.append("/");
    std::string cln = filename;
    cln.erase(cln.begin(), cln.begin()+3);
    cache_path.append(cln);

    fs::path c(cache_path);
    c = c.parent_path();
    fs::create_directories(c);

    FILE *f = fopen(cache_path.c_str(), "wb");
    if (f == NULL) {
        LOG_F(ERROR, "failed to open build cache file %s", cache_path.c_str());
        exit(-1);
    }
    fwrite(data, sizeof(char), data_size, f);
    fclose(f);
    HANDLE real_file_h = CreateFileA(filename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE cache_file_h = CreateFileA(cache_path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    FILETIME ft;

    GetFileTime(real_file_h, NULL, NULL, &ft);
    SetFileTime(cache_file_h, NULL, NULL, &ft);

    LOG_F(MAX, "installed log cache for %s", cache_path.c_str());
}

