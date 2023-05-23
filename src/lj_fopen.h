#ifndef LJ_FILE_OPEN_H
#define LJ_FILE_OPEN_H

#include <stdio.h>

#ifdef _WIN32
FILE *fopenf(const char *filename, const char *mode);
#else
#define fopenf(file, mode) fopen(file, mode)
#endif

#endif // LJ_FILE_OPEN_H