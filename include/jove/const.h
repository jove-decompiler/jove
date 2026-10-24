#ifndef __cplusplus
#error
#endif

template <bool IsConst, typename T>
using perhaps_const = std::conditional_t<IsConst, const T, T>;
