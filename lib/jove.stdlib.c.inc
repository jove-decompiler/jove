static _UNUSED void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

static _UNUSED void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

static _UNUSED void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

static _UNUSED int _memcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0) {
    const unsigned char *p1 = s1, *p2 = s2;

    do {
      if (*p1++ != *p2++)
        return (*--p1 - *--p2);
    } while (--n != 0);
  }
  return (0);
}

static _UNUSED void *_memmem(const void *l, size_t l_len, const void *s, size_t s_len) {
  const char *cl = (const char *)l;
  const char *cs = (const char *)s;

  if (l_len == 0 || s_len == 0)
    return NULL;

  if (l_len < s_len)
    return NULL;

  if (s_len == 1)
    return _memchr(l, (int)*cs, l_len);

  char *const last = (char *)cl + l_len - s_len;

  for (char *cur = (char *)cl; cur <= last; cur++)
    if (cur[0] == cs[0] && _memcmp(cur, cs, s_len) == 0)
      return cur;

  return NULL;
}

static _UNUSED size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

static _UNUSED char *_strcat(char *s, const char *append) {
  char *save = s;

  for (; *s; ++s)
    ;
  while ((*s++ = *append++) != '\0')
    ;
  return (save);
}

static _UNUSED char *_strcpy(char *to, const char *from) {
  char *save = to;

  for (; (*to = *from) != '\0'; ++from, ++to)
    ;
  return (save);
}

static _UNUSED int _strcmp(const char *s1, const char *s2) {
  while (*s1 == *s2++)
    if (*s1++ == 0)
      return (0);
  return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

static _UNUSED int _strncmp(const char *s1, const char *s2, size_t n) {
  if (n == 0)
    return (0);
  do {
    if (*s1 != *s2++)
      return (*(unsigned char *)s1 - *(unsigned char *)--s2);
    if (*s1++ == 0)
      break;
  } while (--n != 0);
  return (0);
}

static char *_uint_to_string(uint64_t x, char *Str, unsigned Radix) {
  // First, check for a zero value and just short circuit the logic below.
  if (x == 0) {
    *Str++ = '0';

    // null-terminate
    *Str = '\0';
    return Str;
  }

  static const char Digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

  char Buffer[65];
  char *BufPtr = &Buffer[sizeof(Buffer)];

  uint64_t N = x;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *p = BufPtr; p != &Buffer[sizeof(Buffer)]; ++p)
    *Str++ = *p;

  // null-terminate
  *Str = '\0';
  return Str;
}

static _UNUSED char *_int_to_string(int64_t x, char *Str, unsigned Radix) {
  uint64_t ux = (uint64_t)x;

  if (x < 0) {
    ux = (uint64_t)(-x);
    *Str++ = '-';
  }

  return _uint_to_string(ux, Str, Radix);
}
