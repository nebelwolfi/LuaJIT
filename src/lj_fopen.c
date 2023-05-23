#include "lj_fopen.h"

#ifdef _WIN32
#include <windows.h>
static int
windows_filename(const char * utf8filename, int usz, wchar_t * winbuffer, int wsz) {
    wsz = MultiByteToWideChar(CP_UTF8, 0, utf8filename, usz, winbuffer, wsz);
    return wsz;
}

FILE *fopenf(const char *filename, const char *mode){
    size_t sz = strlen(filename);
    wchar_t path[4096];
    int winsz = windows_filename(filename, sz, path, sz);
    path[winsz] = 0;

    wchar_t wmode[4096];
    size_t n = strlen(mode);
    winsz = windows_filename(mode, sz, wmode, sz);
    wmode[n] = 0;

    FILE * fp = _wfopen(path, wmode);
    return fp;
}

#endif