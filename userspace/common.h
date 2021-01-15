#pragma once
#include <Windows.h>
#include "ntdll_undocnt.h"

#undef _AMD64_
#define _AMD64_ 1

#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000

#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

#define XALIGN_DOWN(_x_, _align_) ((_x_) & ~((_align_) - 1))
#define XALIGN_UP(_x_, _align_) (((_x_) & ((_align_) - 1)) ? XALIGN_DOWN((_x_), (_align_)) + (_align_) : (_x_))

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

#define GET_NATIVE(_name_)                                      \
                                                                \
    func_##_name_ f_##_name_ = (func_##_name_)GetProcAddress(   \
        GetModuleHandleA("ntdll.dll"),                          \
        (#_name_)                                               \
    );

#define UNICODE_FROM_WCHAR(_us_, _str_)                         \
                                                                \
    ((PUNICODE_STRING)(_us_))->Buffer = (_str_);                \
    ((PUNICODE_STRING)(_us_))->Length =                         \
    ((PUNICODE_STRING)(_us_))->MaximumLength =                  \
    (USHORT)wcslen((_str_)) * sizeof(WCHAR);

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifdef _X86_

#define IFMT IFMT32
#define IFMT_W IFMT32_W

#elif _AMD64_

#define IFMT IFMT64
#define IFMT_W IFMT64_W

#endif

#define MAX_STRING_SIZE 255
