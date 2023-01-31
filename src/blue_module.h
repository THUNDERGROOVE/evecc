#pragma once

#ifdef _DEBUG
#undef _DEBUG
#include <Python.h>
#define _DEBUG
#endif

#include "Python.h"

PyMODINIT_FUNC initblue(void);

void set_password(char *password);
