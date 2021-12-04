
#include <cstdint>
#include <cstdio>

#include "VMProtectSDK.h"

#if _M_X64 || __x86_64__
#pragma comment(lib, "VMProtectSDK64.lib")
#elif _M_IX86 || __i386__
#pragma comment(lib, "VMProtectSDK32.lib")
#endif

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
    VMProtectBegin(__FUNCTION__);
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

__declspec(dllexport, noinline) int func_loop2()
{
    int a = 1;
    for (int i=0; i<2; i++)
    {
        a++;
    }
    return a;
}

__declspec(dllexport, noinline) int func_call2(int a)
{
    printf_s("%d \r\n", a);
    return a;
}

__declspec(dllexport, noinline) void string1()
{
    auto str = VMProtectDecryptStringA("Hello");
    printf_s("%s\r\n", str);
    VMProtectFreeString(str);
}


extern "C" int __stdcall func1();
extern "C" int __stdcall func2();
extern "C" int __stdcall func3();
extern "C" int __stdcall func4();
extern "C" int __stdcall func5();
extern "C" int __stdcall func_call();
extern "C" int __stdcall func_loop();
extern "C" int __fastcall func_cmp();

int main()
{
    func_call();
    printf("func1: %08x \n", func1());
    printf("func2: %08x \n", func2());
    printf("func3: %08x \n", func3());
    printf("func4: %08x \n", func4());
    printf("func5: %08x \n", func5());

    printf("func_call: %08x \n", func_call());
    printf("func_call: %08x \n", func_call2(1));
    printf("func_loop: %08x \n", func_loop());
    printf("func_loop: %08x \n", func_loop2());

    printf("func_complex: %x \n", test_entry_point(3, 17));


    printf("string: "); string1();

    getchar();
    return 0;
}
