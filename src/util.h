#pragma once

#include <stdint.h>

template <typename T, size_t N>
constexpr size_t countof(T(&)[N]) {
	return N;
}

#pragma pack(push, 1)
struct PyPacket {
	uint32_t unk1; // Always 1
	char uhh[2]; // Always Py (0x50 0x79)
	char uhh1; // 1b
	char uhh2; // 1e
	uint32_t not_size;
	//char uhh3; // 38
	//char uhh4; // 00
	//char uhh5; // 00
	//char uhh6; // 00
	uint32_t unk2; // Always ffffffff ; One of the colloring may be the CRC?
	uint32_t unk3; // Always 00000000

};
#pragma pack()

#define HasFile(name) !(INVALID_FILE_ATTRIBUTES == GetFileAttributes(name) && GetLastError() == ERROR_FILE_NOT_FOUND)

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len);
wchar_t* chartow(const char* text);
int hctoi(const char h);
const char *str_ext(const char *filename);
