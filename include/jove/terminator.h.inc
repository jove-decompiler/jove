#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

enum class TERMINATOR : uint8_t {
  UNKNOWN,
  UNCONDITIONAL_JUMP,
  NONE,
  CALL,
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  RETURN,
  UNREACHABLE
};

static inline const char *string_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "UNKNOWN";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "UNCONDITIONAL_JUMP";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "CONDITIONAL_JUMP";
  case TERMINATOR::INDIRECT_CALL:
    return "INDIRECT_CALL";
  case TERMINATOR::INDIRECT_JUMP:
    return "INDIRECT_JUMP";
  case TERMINATOR::CALL:
    return "CALL";
  case TERMINATOR::RETURN:
    return "RETURN";
  case TERMINATOR::UNREACHABLE:
    return "UNREACHABLE";
  case TERMINATOR::NONE:
    return "NONE";
  }

  return "";
}

static inline const char *description_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "<?>";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "<unconditional jump>";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "<conditional jump>";
  case TERMINATOR::INDIRECT_CALL:
    return "<indirect call>";
  case TERMINATOR::INDIRECT_JUMP:
    return "<indirect jump>";
  case TERMINATOR::CALL:
    return "<call>";
  case TERMINATOR::RETURN:
    return "<return>";
  case TERMINATOR::UNREACHABLE:
    return "<unreachable>";
  case TERMINATOR::NONE:
    return "<none>";
  }

  return "";
}

struct terminator_info_t {
  TERMINATOR Type = TERMINATOR::UNKNOWN;
  taddr_t Addr = uninit_taddr;

  struct {
    struct {
      taddr_t Target;
    } _unconditional_jump;

    struct {
      taddr_t Target;
      taddr_t NextPC;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
      bool String = false;
#endif
    } _conditional_jump;

    struct {
      taddr_t Target;
      taddr_t NextPC;
    } _call;

    struct {
      taddr_t NextPC;
    } _indirect_call;

    [[no_unique_address]]
    struct {
    } _indirect_jump;

    [[no_unique_address]]
    struct {
    } _return;

    [[no_unique_address]]
    struct {
    } _unreachable;

    struct {
      taddr_t NextPC;
    } _none;
  };
};

static inline std::string
description_of_terminator_info(const terminator_info_t &T,
                               bool zero_padded = true) {
  std::string res;
  res += description_of_terminator(T.Type);
  res += " @ ";
  res += taddr2str(T.Addr, zero_padded);
  res += " {";

  switch (T.Type) {
  case TERMINATOR::UNKNOWN:
    break;
  case TERMINATOR::UNCONDITIONAL_JUMP:
    res += " -> ";
    res += taddr2str(T._unconditional_jump.Target, zero_padded);
    break;
  case TERMINATOR::CONDITIONAL_JUMP:
    res += " -> ";
    res += taddr2str(T._conditional_jump.Target, zero_padded);
    res += ", ";
    res += taddr2str(T._conditional_jump.NextPC, zero_padded);
    break;
  case TERMINATOR::INDIRECT_CALL:
    res += " ->_ ";
    res += taddr2str(T._indirect_call.NextPC, zero_padded);
    break;
  case TERMINATOR::INDIRECT_JUMP:
    break;
  case TERMINATOR::CALL:
    res += " -> ";
    res += taddr2str(T._call.Target, zero_padded);
    res += ", ";
    res += " ->_ ";
    res += taddr2str(T._call.NextPC, zero_padded);
    break;
  case TERMINATOR::RETURN:
    break;
  case TERMINATOR::UNREACHABLE:
    break;
  case TERMINATOR::NONE:
    res += " _->_ ";
    res += taddr2str(T._none.NextPC, zero_padded);
    break;
  }

  res += "}";

  return res;
}
