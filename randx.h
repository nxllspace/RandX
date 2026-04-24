#pragma once
#ifndef _RANDX_H
#define _RANDX_H

#include <corecrt.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _RANDXIMP
    #if defined(_RANDX_EXPORTS)
        #define _RANDXIMP __declspec(dllexport)
    #else
        #define _RANDXIMP __declspec(dllimport)
    #endif
#endif

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Core API
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

_Check_return_
_Success_(return != 0)
_RANDXIMP int __cdecl randx_fill(
    _Out_writes_bytes_(_Size) void* _Buffer,
    _In_ size_t _Size
    );

_Check_return_
_Success_(return != 0)
_RANDXIMP int __cdecl randx_bytes(
    _Out_writes_bytes_(_Size) void* _Buffer,
    _In_ size_t _Size
    );

_Check_return_
_RANDXIMP uint64_t __cdecl randx_u64(
    void
    );

_Check_return_
_RANDXIMP uint32_t __cdecl randx_u32(
    void
    );

_Check_return_
_RANDXIMP int __cdecl randx_range(
    _In_ int _Min,
    _In_ int _Max
    );

_Check_return_
_RANDXIMP int __cdecl randx_bool(
    void
    );

_Check_return_
_RANDXIMP float __cdecl randx_f32(
    void
    );

_Check_return_
_RANDXIMP double __cdecl randx_f64(
    void
    );

_Check_return_
_Success_(return == 0)
_RANDXIMP errno_t __cdecl randx_hex(
    _Out_writes_z_(_BufferCount) char* _Buffer,
    _In_ size_t _BufferCount
    );

_Check_return_
_RANDXIMP int __cdecl randx_has_rdseed(
    void
    );

_Check_return_
_RANDXIMP int __cdecl randx_has_rdrand(
    void
    );

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// C++ Convenience Wrappers
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

namespace randx
{
    inline bool fill(
        void*  _Buffer,
        size_t _Size
        ) noexcept
    {
        return randx_fill(_Buffer, _Size) != 0;
    }

    inline bool bytes(
        void*  _Buffer,
        size_t _Size
        ) noexcept
    {
        return randx_bytes(_Buffer, _Size) != 0;
    }

    inline uint64_t u64(
        void
        ) noexcept
    {
        return randx_u64();
    }

    inline uint32_t u32(
        void
        ) noexcept
    {
        return randx_u32();
    }

    inline int range(
        int _Min,
        int _Max
        ) noexcept
    {
        return randx_range(_Min, _Max);
    }

    inline bool boolean(
        void
        ) noexcept
    {
        return randx_bool() != 0;
    }

    inline float f32(
        void
        ) noexcept
    {
        return randx_f32();
    }

    inline double f64(
        void
        ) noexcept
    {
        return randx_f64();
    }

    inline bool hex(
        char*  _Buffer,
        size_t _BufferCount
        ) noexcept
    {
        return randx_hex(_Buffer, _BufferCount) == 0;
    }

    inline bool has_rdseed(
        void
        ) noexcept
    {
        return randx_has_rdseed() != 0;
    }

    inline bool has_rdrand(
        void
        ) noexcept
    {
        return randx_has_rdrand() != 0;
    }
}

#endif

#endif // _RANDX_H
