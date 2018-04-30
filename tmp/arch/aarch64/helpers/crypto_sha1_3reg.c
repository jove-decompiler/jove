#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define G_GNUC_NORETURN                         \
  __attribute__((__noreturn__))

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

#define _GLIB_EXTERN extern

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr) G_GNUC_NORETURN;

#include <stddef.h>

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << shift) | (word >> ((32 - shift) & 31));
}

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((32 - shift) & 31));
}

#define HELPER(name) glue(helper_, name)

#define CR_ST_WORD(state, i)   (state.words[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

static uint32_t cho(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & (y ^ z)) ^ z;
}

static uint32_t par(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((x | y) & z);
}

void HELPER(crypto_sha1_3reg)(void *vd, void *vn, void *vm, uint32_t op)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;
    union CRYPTO_STATE d = { .l = { rd[0], rd[1] } };
    union CRYPTO_STATE n = { .l = { rn[0], rn[1] } };
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };

    if (op == 3) { /* sha1su0 */
        d.l[0] ^= d.l[1] ^ m.l[0];
        d.l[1] ^= n.l[0] ^ m.l[1];
    } else {
        int i;

        for (i = 0; i < 4; i++) {
            uint32_t t;

            switch (op) {
            case 0: /* sha1c */
                t = cho(CR_ST_WORD(d, 1), CR_ST_WORD(d, 2), CR_ST_WORD(d, 3));
                break;
            case 1: /* sha1p */
                t = par(CR_ST_WORD(d, 1), CR_ST_WORD(d, 2), CR_ST_WORD(d, 3));
                break;
            case 2: /* sha1m */
                t = maj(CR_ST_WORD(d, 1), CR_ST_WORD(d, 2), CR_ST_WORD(d, 3));
                break;
            default:
                g_assert_not_reached();
            }
            t += rol32(CR_ST_WORD(d, 0), 5) + CR_ST_WORD(n, 0)
                 + CR_ST_WORD(m, i);

            CR_ST_WORD(n, 0) = CR_ST_WORD(d, 3);
            CR_ST_WORD(d, 3) = CR_ST_WORD(d, 2);
            CR_ST_WORD(d, 2) = ror32(CR_ST_WORD(d, 1), 2);
            CR_ST_WORD(d, 1) = CR_ST_WORD(d, 0);
            CR_ST_WORD(d, 0) = t;
        }
    }
    rd[0] = d.l[0];
    rd[1] = d.l[1];
}

