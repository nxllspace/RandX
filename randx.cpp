#include "randx.h"

#ifndef NOMINMAX
    #define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <immintrin.h>

#include <errno.h>
#include <limits.h>
#include <float.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Internal CPU Feature Checks
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

static
_Check_return_
int
__cdecl
__randx_cpu_supports_rdrand(
    void
    )
{
    int _Info[4] = {};

    __cpuid(_Info, 1);

    return (_Info[2] & (1 << 30)) != 0;
}

static
_Check_return_
int
__cdecl
__randx_cpu_supports_rdseed(
    void
    )
{
    int _Info[4] = {};

    __cpuidex(_Info, 7, 0);

    return (_Info[1] & (1 << 18)) != 0;
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Internal Hardware RNG Helpers
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

static
_Check_return_
int
__cdecl
__randx_hw_rdseed64(
    _Out_ uint64_t* _Value
    )
{
#if defined(_M_X64)
    unsigned __int64 _Result = 0;

    if (_rdseed64_step(&_Result))
    {
        *_Value = (uint64_t)_Result;
        return 1;
    }
#else
    (void)_Value;
#endif

    return 0;
}

static
_Check_return_
int
__cdecl
__randx_hw_rdrand64(
    _Out_ uint64_t* _Value
    )
{
#if defined(_M_X64)
    unsigned __int64 _Result = 0;

    if (_rdrand64_step(&_Result))
    {
        *_Value = (uint64_t)_Result;
        return 1;
    }
#else
    (void)_Value;
#endif

    return 0;
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Internal OS RNG Fallback
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

static
_Check_return_
_Success_(return != 0)
int
__cdecl
__randx_os_fill(
    _Out_writes_bytes_(_Size) void* _Buffer,
    _In_ size_t _Size
    )
{
    if (_Size == 0)
    {
        return 1;
    }

    return BCryptGenRandom(
        nullptr,
        static_cast<PUCHAR>(_Buffer),
        static_cast<ULONG>(_Size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
        ) == 0;
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Core Fill Implementation
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

_Check_return_
_Success_(return != 0)
int
__cdecl
randx_fill(
    _Out_writes_bytes_(_Size) void* _Buffer,
    _In_ size_t _Size
    )
{
    unsigned char* _Data;
    size_t         _Offset;

    if (_Buffer == nullptr && _Size != 0)
    {
        return 0;
    }

    if (_Size == 0)
    {
        return 1;
    }

    _Data   = static_cast<unsigned char*>(_Buffer);
    _Offset = 0;

    if (__randx_cpu_supports_rdseed())
    {
        while (_Offset + sizeof(uint64_t) <= _Size)
        {
            uint64_t _Chunk   = 0;
            int      _Success = 0;
            int      _Attempt;

            for (_Attempt = 0; _Attempt != 32; ++_Attempt)
            {
                if (__randx_hw_rdseed64(&_Chunk))
                {
                    _Success = 1;
                    break;
                }
            }

            if (!_Success)
            {
                break;
            }

            memcpy(_Data + _Offset, &_Chunk, sizeof(_Chunk));
            _Offset += sizeof(_Chunk);
        }
    }

    if (_Offset < _Size && __randx_cpu_supports_rdrand())
    {
        while (_Offset + sizeof(uint64_t) <= _Size)
        {
            uint64_t _Chunk   = 0;
            int      _Success = 0;
            int      _Attempt;

            for (_Attempt = 0; _Attempt != 32; ++_Attempt)
            {
                if (__randx_hw_rdrand64(&_Chunk))
                {
                    _Success = 1;
                    break;
                }
            }

            if (!_Success)
            {
                break;
            }

            memcpy(_Data + _Offset, &_Chunk, sizeof(_Chunk));
            _Offset += sizeof(_Chunk);
        }
    }

    if (_Offset < _Size)
    {
        return __randx_os_fill(_Data + _Offset, _Size - _Offset);
    }

    return 1;
}

_Check_return_
_Success_(return != 0)
int
__cdecl
randx_bytes(
    _Out_writes_bytes_(_Size) void* _Buffer,
    _In_ size_t _Size
    )
{
    return randx_fill(_Buffer, _Size);
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Internal Bounded-Range Helpers
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

static
_Check_return_
uint32_t
__cdecl
__randx_bounded_u32(
    _In_ uint32_t _Max_exclusive
    )
{
    uint32_t _Threshold;

    if (_Max_exclusive == 0)
    {
        return 0;
    }

    _Threshold = (UINT_MAX - _Max_exclusive + 1u) % _Max_exclusive;

    for (;;)
    {
        uint32_t _Value = 0;

        if (!randx_fill(&_Value, sizeof(_Value)))
        {
            return 0;
        }

        if (_Value >= _Threshold)
        {
            return _Value % _Max_exclusive;
        }
    }
}

static
_Check_return_
uint64_t
__cdecl
__randx_bounded_u64(
    _In_ uint64_t _Max_exclusive
    )
{
    uint64_t _Threshold;

    if (_Max_exclusive == 0)
    {
        return 0;
    }

    _Threshold = (UINT64_MAX - _Max_exclusive + 1ull) % _Max_exclusive;

    for (;;)
    {
        uint64_t _Value = 0;

        if (!randx_fill(&_Value, sizeof(_Value)))
        {
            return 0;
        }

        if (_Value >= _Threshold)
        {
            return _Value % _Max_exclusive;
        }
    }
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Public Scalar APIs
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

_Check_return_
uint64_t
__cdecl
randx_u64(
    void
    )
{
    uint64_t _Value = 0;

    (void)randx_fill(&_Value, sizeof(_Value));

    return _Value;
}

_Check_return_
uint32_t
__cdecl
randx_u32(
    void
    )
{
    uint32_t _Value = 0;

    (void)randx_fill(&_Value, sizeof(_Value));

    return _Value;
}

_Check_return_
int
__cdecl
randx_range(
    _In_ int _Min,
    _In_ int _Max
    )
{
    uint64_t _Span64;

    if (_Min >= _Max)
    {
        return _Min;
    }

    _Span64 = (uint64_t)((int64_t)_Max - (int64_t)_Min) + 1ull;

    if (_Span64 == 0ull)
    {
        return _Min;
    }

    if (_Span64 <= (uint64_t)UINT32_MAX)
    {
        return _Min + (int)__randx_bounded_u32((uint32_t)_Span64);
    }

    return (int)((int64_t)_Min + (int64_t)__randx_bounded_u64(_Span64));
}

_Check_return_
int
__cdecl
randx_bool(
    void
    )
{
    return (randx_u32() & 1u) != 0u;
}

_Check_return_
float
__cdecl
randx_f32(
    void
    )
{
    uint32_t _Value;

    _Value = randx_u32();

    return (float)((double)_Value / ((double)UINT32_MAX + 1.0));
}

_Check_return_
double
__cdecl
randx_f64(
    void
    )
{
    uint64_t _Value;

    _Value = randx_u64();

    return (double)((long double)_Value / ((long double)UINT64_MAX + 1.0L));
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Public Formatting Helpers
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

_Check_return_
_Success_(return == 0)
errno_t
__cdecl
randx_hex(
    _Out_writes_z_(_BufferCount) char* _Buffer,
    _In_ size_t _BufferCount
    )
{
    static char const _Digits[] = "0123456789abcdef";

    size_t        _Byte_count;
    size_t        _Index;
    unsigned char _Byte;

    if (_Buffer == nullptr)
    {
        return EINVAL;
    }

    if (_BufferCount == 0)
    {
        return EINVAL;
    }

    _Buffer[0] = '\0';

    if (((_BufferCount - 1u) & 1u) != 0u)
    {
        return EINVAL;
    }

    _Byte_count = (_BufferCount - 1u) / 2u;

    if (_Byte_count == 0)
    {
        return EINVAL;
    }

    for (_Index = 0; _Index != _Byte_count; ++_Index)
    {
        if (!randx_fill(&_Byte, sizeof(_Byte)))
        {
            _Buffer[0] = '\0';
            return EINVAL;
        }

        _Buffer[_Index * 2u + 0u] = _Digits[(_Byte >> 4) & 0x0F];
        _Buffer[_Index * 2u + 1u] = _Digits[_Byte & 0x0F];
    }

    _Buffer[_Byte_count * 2u] = '\0';

    return 0;
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Public Feature Queries
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

_Check_return_
int
__cdecl
randx_has_rdseed(
    void
    )
{
    return __randx_cpu_supports_rdseed();
}

_Check_return_
int
__cdecl
randx_has_rdrand(
    void
    )
{
    return __randx_cpu_supports_rdrand();
}
