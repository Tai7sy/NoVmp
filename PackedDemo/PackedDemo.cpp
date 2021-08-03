
#include <stdio.h>


extern "C" int __stdcall func1();

int main()
{
    func1();
    return 0;
}
