typedef raw_spinlock_t jove_spinlock_t;
#define DEFINE_JOVE_SPINLOCK(...) DEFINE_RAW_SPINLOCK(__VA_ARGS__)
#define _jove_spin_lock(l)     ticket_spin_lock(&(l).raw_lock)
#define _jove_spin_unlock(l) ticket_spin_unlock(&(l).raw_lock)
