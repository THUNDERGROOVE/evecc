//
// Created by nick on 2/10/2023.
//

#ifndef EVECC_PY_BUILD_CACHE_H
#define EVECC_PY_BUILD_CACHE_H

#include "crc32c/crc32c.h"

char *get_cache(int32_t *data_size, std::string filename);
void install_cache(std::string filename, char *data, int32_t data_size);
void set_do_build_cache(bool do_cache);

#endif //EVECC_PY_BUILD_CACHE_H
