#include <Windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>


WINBASEAPI int _cdecl MSVCRT$printf(const char* _Format, ...);

void go(char* in, unsigned long long datalen) {
	MSVCRT$printf("Test");
}