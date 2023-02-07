#pragma once

#define Py_NO_ENABLE_SHARED
#include "Python.h"

PyMODINIT_FUNC initblue(void);

void set_password(char *password);
