#include "lj_def.h"
#include "lj_arch.h"
#include "lj_alloc.h"
#include "lj_prng.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void* SusAlloc(void* you_wish, size_t dwSize, unsigned int flAllocationType, unsigned int flags)
{
    void* v = VirtualAlloc(you_wish, dwSize + 0x100, flAllocationType, flags);
    if (v == NULL)
        return NULL;

    unsigned int SuperJunk = 0xDEADC0DE;
    for (unsigned int i = 0; i < 0x50 / sizeof(unsigned int); ++i)
    {
        SuperJunk ^= (i << (i % 32));
        SuperJunk -= 0x11111111;
        ((unsigned int*)((uintptr_t)v + dwSize))[i] = SuperJunk;
    }

    return (void*)((uintptr_t)v);
}