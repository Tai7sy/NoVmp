
#include <cstdint>
#include <cstdio>

#include "VMProtectSDK.h"

#if _M_X64 || __x86_64__
#pragma comment(lib, "VMProtectSDK64.lib")
#elif _M_IX86 || __i386__
#pragma comment(lib, "VMProtectSDK32.lib")
#endif

extern "C" int __stdcall func1();

static volatile intptr_t _o;

template<typename T>
__forceinline intptr_t test_type(const T& value) // so that we pass a stack
{
    static volatile T _a = 2;
    static volatile T _b = 2;

    volatile T x = value;
    x *= _a;     // IMUL/MUL
    x -= 42;     // Will generate ADD, can deduce SUB
    x &= ~0b1;   // NOT, AND
    x <<= 1;     // SHL
    x ^= 1;      // Will generate OR, can deduce OR
    // x /= _b;  // IDIV / DIV
    x = (x << 3) | (x >> (sizeof(T) * 32 - 3)); // ROT
    _o = x;      // SX
    return _o;
}
__declspec(dllexport, noinline) int test_entry_point(intptr_t r, intptr_t b)
{
    VMProtectBegin(0);
    int k = 4;
    for (int i = 0; i < 8; i++, r++, b--) {
        k += printf("uint8_t:  %p\n", test_type<uint8_t>(r * b));
        k += printf("uint16_t: %p\n", test_type<uint16_t>(r * b));
        k += printf("uint32_t: %p\n", test_type<uint32_t>(r * b));
        k += printf("uint64_t: %p\n", test_type<uint64_t>(r * b));
        k += printf("int8_t:   %p\n", test_type<int8_t>(r * b));
        k += printf("int16_t:  %p\n", test_type<int16_t>(r * b));
        k += printf("int32_t:  %p\n", test_type<int32_t>(r * b));
        k += printf("int64_t:  %p\n", test_type<int64_t>(r * b));
    }
    VMProtectEnd();
    return k;
}

int main()
{
    func1();
    auto val = test_entry_point(3, 17);
    printf("Output: %x \n", val);
    getchar();
    return 0;
}
