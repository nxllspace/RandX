# RandX

Lightweight random generation library for Windows written in C/C++.

`RandX` uses hardware random instructions (`RDSEED` / `RDRAND`) when available and automatically falls back to the Windows cryptographic RNG (`BCryptGenRandom`).

## Features

* Hardware-backed random generation
* Automatic fallback to OS RNG
* Simple C API
* C++ convenience wrappers
* Random integers, floats, booleans, ranges, and hex generation
* Tiny single-header + single-source implementation

## Files

* `randx.h` — public API
* `randx.cpp` — implementation

## API

```cpp
randx_fill(buffer, size);
randx_bytes(buffer, size);

randx_u64();
randx_u32();

randx_range(min, max);
randx_bool();

randx_f32();
randx_f64();

randx_hex(buffer, size);
```

## Example

```cpp
#include "randx.h"
#include <iostream>

int main()
{
    uint64_t value = randx_u64();

    std::cout << value << std::endl;

    return 0;
}
```

## Build

### MSVC

```bat
cl /EHsc /O2 randx.cpp
```

The library links against:

```txt
bcrypt.lib
```

## Notes

* `RDSEED` is preferred when supported by the CPU
* `RDRAND` is used as secondary hardware entropy source
* Falls back to `BCryptGenRandom` if hardware RNG is unavailable
* Designed for modern Windows systems

## License

MIT License
