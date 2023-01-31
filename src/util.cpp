#include <stdlib.h>
#include <string.h>
#include <ctype.h>

const char *str_ext(const char *filename) {
	const char *dot = strrchr(filename, '.');
	if (!dot || dot == filename) return "";
	return dot + 1;
}

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len) {
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	if (l_len == 0 || s_len == 0)
		return NULL;

	if (l_len < s_len)
		return NULL;

	if (s_len == 1)
		return (void *)memchr(l, (int)*cs, l_len);

	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;

	return NULL;
}
int hctoi(const char h) {
	if (isdigit(h)) {
		return h - '0';
	} else {
		return toupper(h) - 'A' + 10;
	}
}

wchar_t* chartow(const char* text)
{
	size_t size = strlen(text) + 1;
	wchar_t* wa = (wchar_t *)calloc(size, sizeof(wchar_t));
	mbstowcs(wa, text, size);
	return wa;
}

/*
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
	int needle_first;
	const void *p = haystack;
	size_t plen = hlen;

	if (!nlen)
		return NULL;

	needle_first = *(unsigned char *)needle;

	while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1))) {
		if (!memcmp(p, needle, nlen))
			return (void *)p;

		p = ((char *)p) + 1;
		plen = hlen - ((char *)p - haystack);
	}

	return NULL;
}
*/