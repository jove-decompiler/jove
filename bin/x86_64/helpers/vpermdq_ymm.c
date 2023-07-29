#include <stdint.h>

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

# define G_NORETURN __attribute__ ((__noreturn__))

#define _GLIB_EXTERN extern

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
G_NORETURN
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr);

#include <stddef.h>

typedef uint16_t float16;

typedef uint32_t float32;

typedef uint64_t float64;

typedef union XMMReg {
    uint64_t _q_XMMReg[128 / 64];
} XMMReg;

typedef union YMMReg {
    uint64_t _q_YMMReg[256 / 64];
    XMMReg   _x_YMMReg[256 / 128];
} YMMReg;

typedef union ZMMReg {
    uint8_t  _b_ZMMReg[512 / 8];
    uint16_t _w_ZMMReg[512 / 16];
    uint32_t _l_ZMMReg[512 / 32];
    uint64_t _q_ZMMReg[512 / 64];
    float16  _h_ZMMReg[512 / 16];
    float32  _s_ZMMReg[512 / 32];
    float64  _d_ZMMReg[512 / 64];
    XMMReg   _x_ZMMReg[512 / 128];
    YMMReg   _y_ZMMReg[512 / 256];
} ZMMReg;

#define ZMM_Q(n) _q_ZMMReg[n]

#define Reg ZMMReg

#define Q(n) ZMM_Q(n)

void helper_vpermdq_ymm(Reg *d, Reg *v, Reg *s, uint32_t order)
{
    uint64_t r0, r1, r2, r3;

    switch (order & 3) {
    case 0:
        r0 = v->Q(0);
        r1 = v->Q(1);
        break;
    case 1:
        r0 = v->Q(2);
        r1 = v->Q(3);
        break;
    case 2:
        r0 = s->Q(0);
        r1 = s->Q(1);
        break;
    case 3:
        r0 = s->Q(2);
        r1 = s->Q(3);
        break;
    default: /* default case added to help the compiler to avoid warnings */
        g_assert_not_reached();
    }
    switch ((order >> 4) & 3) {
    case 0:
        r2 = v->Q(0);
        r3 = v->Q(1);
        break;
    case 1:
        r2 = v->Q(2);
        r3 = v->Q(3);
        break;
    case 2:
        r2 = s->Q(0);
        r3 = s->Q(1);
        break;
    case 3:
        r2 = s->Q(2);
        r3 = s->Q(3);
        break;
    default: /* default case added to help the compiler to avoid warnings */
        g_assert_not_reached();
    }
    d->Q(0) = r0;
    d->Q(1) = r1;
    d->Q(2) = r2;
    d->Q(3) = r3;
    if (order & 0x8) {
        d->Q(0) = 0;
        d->Q(1) = 0;
    }
    if (order & 0x80) {
        d->Q(2) = 0;
        d->Q(3) = 0;
    }
}

