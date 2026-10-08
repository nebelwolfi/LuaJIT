#include "lj_fopen.h"

#ifdef _WIN32
#include <windows.h>
#include <errno.h>

#define FOPENF_PATH_MAX (MAX_PATH * 16)
#define FOPENF_MODE_MAX 64

/* Each string is converted on its own NUL (cbMultiByte -1) and into its own
 * buffer size. Both used to take the FILENAME's length: the mode was read that
 * many bytes past its start, and a filename longer than the buffer ran over it. */
static int
windows_string(const char * utf8, wchar_t * winbuffer, int wsz) {
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, winbuffer, wsz) > 0)
        return 1;
    errno = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? ENAMETOOLONG : EINVAL;
    return 0;
}

FILE *fopenf(const char *filename, const char *mode){
    wchar_t path[FOPENF_PATH_MAX];
    wchar_t wmode[FOPENF_MODE_MAX];

    if (!windows_string(filename, path, FOPENF_PATH_MAX))
        return NULL;
    if (!windows_string(mode, wmode, FOPENF_MODE_MAX))
        return NULL;

    FILE * fp = _wfopen(path, wmode);
    return fp;
}

#endif
