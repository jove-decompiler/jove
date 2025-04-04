#pragma once

#if defined(WARN) || defined(WARN_ON)
#error
#endif

#define WARN()                                                                 \
  do {                                                                         \
    this->warn(__FILE__, __LINE__);                                                \
  } while (0)

#define WARN_ON(condition)                                                     \
  ({                                                                           \
    int __ret_warn_on = !!(condition);                                         \
    if (unlikely(__ret_warn_on))                                               \
      WARN();                                                                  \
    unlikely(__ret_warn_on);                                                   \
  })
