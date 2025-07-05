//
// this code is paired with tools/jove-recover.cpp
//

void _jove_recover_dyn_target(uint32_t CallerBBIdx, uintptr_t CalleeAddr) {
  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } Callee;

  //
  // lookup in __jove_function_map
  //
#if 0
  memory_barrier();

  {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "dumping __jove_function_map...\n");
    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  {
    int bkt;
    struct jove_function_info_t *x;

    hash_for_each(__jove_function_map, bkt, x, hlist) {
      {
        char s[1024];
        s[0] = '\0';

        _strcat(s, "0x");
        {
          char buff[65];
          _uint_to_string(x->pc, buff, 0x10);

          _strcat(s, buff);
        }
        _strcat(s, " (");
        {
          char buff[65];
          _uint_to_string(x->BIdx, buff, 10);

          _strcat(s, buff);
        }
        _strcat(s, ", ");
        {
          char buff[65];
          _uint_to_string(x->FIdx, buff, 10);

          _strcat(s, buff);
        }
        _strcat(s, ")\n");

        _jove_robust_write(2 /* stderr */, s, _strlen(s));
      }
    }
  }
#endif
  {
    struct jove_function_info_t *finfo;

    hash_for_each_possible(__jove_function_map, finfo, hlist, CalleeAddr) {
      if (finfo->pc != CalleeAddr) {
        continue;
      } else {
        Callee.BIdx = finfo->BIdx;
        Callee.FIdx = finfo->FIdx;

        goto found;
      }
    }
  }

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *fns = __jove_function_tables[BIdx];
    if (!fns) {
      if (BIdx == 1 || BIdx == 2) { /* XXX */
        fns = __jove_foreign_function_tables[BIdx];
        if (!fns)
          continue;
      } else {
        continue;
      }
    }

    if (BIdx == 1 || BIdx == 2) { /* XXX */
      for (unsigned FIdx = 0; fns[FIdx]; ++FIdx) {
        if (CalleeAddr == fns[FIdx]) {
          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          goto found;
        }
      }
    } else {
      for (unsigned FIdx = 0; fns[3 * FIdx]; ++FIdx) {
        if (CalleeAddr == fns[3 * FIdx + 0]) {
          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          goto found;
        }
      }
    }
  }

  unsigned N = _jove_foreign_lib_count();

  bool FoundAll = true;
  for (unsigned j = 3; j < N + 3; ++j) {
    if (__jove_foreign_function_tables[j] == NULL) {
      FoundAll = false;
      break;
    }
  }

  if (!FoundAll) {
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          goto matched;
        }
        }
      }
matched:
    }
  }

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      if (!(CalleeAddr >= min && CalleeAddr < max))
        continue;

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match) {
          uintptr_t *ForeignFnTbl = _jove_foreign_lib_function_table(i);

          for (unsigned FIdx = 0; ForeignFnTbl[FIdx]; ++FIdx) {
            if (CalleeAddr == ForeignFnTbl[FIdx]) {
              Callee.BIdx = i + 3;
              Callee.FIdx = FIdx;

              goto found;
            }
          }
        }
        }
      }
    }
  }

  return; /* not found */

found:
  _jove_found_dyn_target(CallerBBIdx, Callee.BIdx, Callee.FIdx);
  _jove_sys_exit_group('f');
  __UNREACHABLE();
}

void _jove_found_dyn_target(uint32_t CallerBBIdx,
                            uint32_t CalleeBIdx,
                            uint32_t CalleeFIdx) {
  uint32_t CallerBIdx = _jove_binary_index();

  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --dyn-target=");
    {
      char buff[65];
      _uint_to_string(_jove_binary_index(), buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(CallerBBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(CalleeBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(CalleeFIdx, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'f';

      {
        char buff[sizeof(char) + 4 * sizeof(uint32_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &CallerBIdx,  sizeof(CallerBIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &CallerBBIdx, sizeof(CallerBBIdx));
        _memcpy(&buff[sizeof(char) + 2 * sizeof(uint32_t)], &CalleeBIdx,  sizeof(CalleeBIdx));
        _memcpy(&buff[sizeof(char) + 3 * sizeof(uint32_t)], &CalleeFIdx,  sizeof(CalleeFIdx));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
    }
  }
}

void _jove_recover_function(uint32_t IndCallBBIdx, uintptr_t FuncAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndCall;

  IndCall.BIdx = _jove_binary_index();
  IndCall.BBIdx = IndCallBBIdx;

  struct {
    uint32_t BIdx;
    uintptr_t Addr;
  } Callee;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *Entry = __jove_sections_tables[BIdx];
    if (likely(!Entry))
      continue;

    struct {
      uintptr_t Beg;
      uintptr_t End;
    } SectionsGlobal;

    uintptr_t SectsStartAddr;

    SectionsGlobal.Beg = Entry[0];
    SectionsGlobal.End = Entry[1];
    SectsStartAddr = Entry[2];

    if (FuncAddr >= SectionsGlobal.Beg && FuncAddr < SectionsGlobal.End) {
      Callee.BIdx = BIdx;
      Callee.Addr = (FuncAddr - SectionsGlobal.Beg) + SectsStartAddr;
      goto found;
    }
  }

  return; /* not found */

found:
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --function=");
    {
      char buff[65];
      _uint_to_string(IndCall.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(IndCall.BBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Callee.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Callee.Addr, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'F';

      {
        char buff[sizeof(char) + 3 * sizeof(uint32_t) + sizeof(uintptr_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &IndCall.BIdx,  sizeof(IndCall.BIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &IndCall.BBIdx, sizeof(IndCall.BBIdx));
        _memcpy(&buff[sizeof(char) + 2 * sizeof(uint32_t)], &Callee.BIdx,   sizeof(Callee.BIdx));
        _memcpy(&buff[sizeof(char) + 3 * sizeof(uint32_t)], &Callee.Addr,   sizeof(Callee.Addr));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_foreign_function(uint32_t IndCallBBIdx,
                                    uintptr_t CalleeAddr) {
  //
  // if it's a trampoline, we want to look at the address in its "slot"
  //
  {
    struct jove_trampoline_t *tramp;
    hash_for_each_possible(__jove_trampolines_pending, tramp, hlist, CalleeAddr) {
      if (tramp->pc == CalleeAddr) {
        CalleeAddr = *tramp->slotp;
        break;
      }
    }
  }

  unsigned N = _jove_foreign_lib_count();

  bool FoundAll = true;
  for (unsigned j = 3; j < N + 3; ++j) {
    if (__jove_foreign_function_tables[j] == NULL) {
      FoundAll = false;
      break;
    }
  }

  if (!FoundAll) {
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          goto matched;
        }
      }
      }
matched:
    }
  }

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      if (!(CalleeAddr >= min && CalleeAddr < max))
        continue;

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match) {
          uintptr_t *ForeignFnTbl = _jove_foreign_lib_function_table(i);

          for (unsigned FIdx = 0; ForeignFnTbl[FIdx]; ++FIdx) {
            if (CalleeAddr == ForeignFnTbl[FIdx]) {
              _UNREACHABLE("foreign function already known");
            }
          }

          // if we get here, it's a function we don't know about.
          _jove_recover_foreign_function_at_offset(IndCallBBIdx, i + 3,
                                                   (CalleeAddr - min) + off);
          _UNREACHABLE();
        }
      }
      }

      return; /* nope */
    }
  }
}

void _jove_recover_foreign_function_at_offset(uint32_t IndCallBBIdx,
                                              uint32_t CalleeBIdx,
                                              uintptr_t CalleeOffset) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndCall;

  IndCall.BIdx = _jove_binary_index();
  IndCall.BBIdx = IndCallBBIdx;

  struct {
    uint32_t BIdx;
    uintptr_t Offset;
  } Callee;

  Callee.BIdx = CalleeBIdx;
  Callee.Offset = CalleeOffset;

found:
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --function-at-offset=");
    {
      char buff[65];
      _uint_to_string(IndCall.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(IndCall.BBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Callee.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Callee.Offset, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'O';

      {
        char buff[sizeof(char) + 3 * sizeof(uint32_t) + sizeof(uintptr_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &IndCall.BIdx,  sizeof(IndCall.BIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &IndCall.BBIdx, sizeof(IndCall.BBIdx));
        _memcpy(&buff[sizeof(char) + 2 * sizeof(uint32_t)], &Callee.BIdx,   sizeof(Callee.BIdx));
        _memcpy(&buff[sizeof(char) + 3 * sizeof(uint32_t)], &Callee.Offset, sizeof(Callee.Offset));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_basic_block(uint32_t IndBrBBIdx, uintptr_t BBAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndBr;

  struct {
    uintptr_t Beg;
    uintptr_t End;
  } SectionsGlobal;

  uintptr_t SectsStartAddr;

  IndBr.BIdx = _jove_binary_index();
  IndBr.BBIdx = IndBrBBIdx;

  SectionsGlobal.Beg = _jove_sections_begin();
  SectionsGlobal.End = _jove_sections_end();
  SectsStartAddr = _jove_sections_start_addr();

  if (!(BBAddr >= SectionsGlobal.Beg && BBAddr < SectionsGlobal.End))
    return; /* not found */

  uintptr_t Addr = (BBAddr - SectionsGlobal.Beg) + SectsStartAddr;

found:
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --basic-block=");
    {
      char buff[65];
      _uint_to_string(IndBr.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(IndBr.BBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Addr, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'b';

      {
        char buff[sizeof(char) + 2 * sizeof(uint32_t) + sizeof(uintptr_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &IndBr.BIdx,  sizeof(IndBr.BIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &IndBr.BBIdx, sizeof(IndBr.BBIdx));
        _memcpy(&buff[sizeof(char) + 2 * sizeof(uint32_t)], &Addr,        sizeof(Addr));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_returned(uint32_t CallerBBIdx) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } Call;

  Call.BIdx = _jove_binary_index();
  Call.BBIdx = CallerBBIdx;

found:
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --returns=");
    {
      char buff[65];
      _uint_to_string(Call.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Call.BBIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'r';

      {
        char buff[sizeof(char) + 2 * sizeof(uint32_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &Call.BIdx,  sizeof(Call.BIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &Call.BBIdx, sizeof(Call.BBIdx));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_ABI(uint32_t FIdx) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } NewABI;

  NewABI.BIdx = _jove_binary_index();
  NewABI.FIdx = FIdx;

found:
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "recover --abi=");
    {
      char buff[65];
      _uint_to_string(NewABI.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(NewABI.FIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'a';

      {
        char buff[sizeof(char) + 2 * sizeof(uint32_t)];

        buff[0] = ch;
        _memcpy(&buff[sizeof(char) + 0 * sizeof(uint32_t)], &NewABI.BIdx, sizeof(NewABI.BIdx));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], &NewABI.FIdx, sizeof(NewABI.FIdx));

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
    }
  }
}

void _jove_recover_foreign_binary_with_path(const char *path) {
  const uint32_t PathLen = _strlen(path);

  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path || __jove_opts.Debug.Verbose) {
    char *buff;
    ___buff___(buff, 2*PATH_MAX);
    buff[0] = '\0';

    _strcat(buff, "recover \"--foreign-binary=");
    _strcat(buff, path);
    _strcat(buff, "\"\n");

    _DUMP(buff);
    if (!recover_fifo_path)
      _UNREACHABLE("missing JOVE_RECOVER_FIFO environment variable");
  }

  {
    int recover_fd = _jove_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0)
      _UNREACHABLE("could not open recover fifo");

    {
      char ch = 'B';

      {
	char *buff;
        ___buff___(buff, PATH_MAX + 1);

        buff[0] = ch;
        _memcpy(&buff[sizeof(char)], &PathLen, sizeof(PathLen));
        _memcpy(&buff[sizeof(char) + 1 * sizeof(uint32_t)], path, PathLen);

        unsigned N = 1 + sizeof(uint32_t) + PathLen;
        if (_jove_sys_write(recover_fd, &buff[0], N) != N)
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_foreign_binary(uintptr_t CalleeAddr) {
  //
  // if it's a trampoline, we want to look at the address in its "slot"
  //
  {
    struct jove_trampoline_t *tramp;
    hash_for_each_possible(__jove_trampolines_pending, tramp, hlist, CalleeAddr) {
      if (tramp->pc == CalleeAddr) {
        CalleeAddr = *tramp->slotp;
        break;
      }
    }
  }

  unsigned N = _jove_foreign_lib_count();

  bool FoundAll = true;
  for (unsigned j = 3; j < N + 3; ++j) {
    if (__jove_foreign_function_tables[j] == NULL) {
      FoundAll = false;
      break;
    }
  }

  if (!FoundAll) {
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          goto matched;
        }
      }
      }
matched:
    }
  }

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      if (!(CalleeAddr >= min && CalleeAddr < max))
        continue;

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match)
          _UNREACHABLE("foreign binary already known");
      }
      }

      char *path = _memchr(line, '/', eol - line);
      if (!path)
        return; /* probably anonymous memory */

      *eol = '\0';
      _jove_recover_foreign_binary_with_path(path);
      __UNREACHABLE();
    }
  }
}

#ifdef JOVE_COFF

void _jove_recover_anonymous_foreign_function(uint32_t BBIdx, uintptr_t pc) {
  _VERBOSE_DUMP_FUNC();
  char *wine_stderr_path = _getenv("WINEDEBUGLOG");
  if (!wine_stderr_path)
    return;

  char *beg;
  ___buff___(beg, JOVE_LARGE_BUFF_SIZE);
  unsigned n =
      _jove_read_pseudo_file(wine_stderr_path, beg, JOVE_LARGE_BUFF_SIZE);

  char *line;
  char *eol;
  for_each_str_eos_delim_know_end(line, eol, '\n', beg, n) {
    unsigned left = eol - line;
    const char *needle1 = ":trace:module:map_image_into_view mapping ";
    char *map_image_into_view = _memmem(line, left, needle1, _strlen(needle1));
    if (!map_image_into_view)
      continue;

    char *path_beg = map_image_into_view + _strlen(needle1);

    char *p = map_image_into_view; /* space */
    left = eol - p;

    // const char *needle2 = "section .text at ";
    const char *needle2 = " section ";

    char *section = _memmem(p, left, needle2, _strlen(needle2));
    if (!section)
      continue;

    char *const path_end = section;

    char *const sectnm_beg = section + _strlen(needle2);
    char *const sectnm_end = _memchr(sectnm_beg, ' ', eol - sectnm_beg);
    _ASSERT(sectnm_end);

    p = sectnm_end;
    _ASSERT(p[0] == ' ' && p[1] == 'a' && p[2] == 't' && p[3] == ' ' &&
            p[4] == '0' && p[5] == 'x');

    char *const min_beg = p + _strlen(" at 0x");
    char *const min_end = _memchr(min_beg, ' ', eol - min_beg);
    _ASSERT(min_end);

    uint64_t min = _u64ofhexstr(min_beg, min_end);

    char *const off_beg = min_end + _strlen(" off ");
    char *const off_end = _memchr(off_beg, ' ', eol - off_beg);
    _ASSERT(off_end);

    uint64_t off = _u64ofhexstr(off_beg, off_end);

    char *const size_beg = off_end + _strlen("size  ");
    char *const size_end = _memchr(size_beg, ' ', eol - size_beg);
    _ASSERT(size_end);

    uint64_t size = _u64ofhexstr(size_beg, size_end);

    if (!(pc >= min && pc < (min + size)))
      continue;

    //
    // found the mapping where the address is located
    //
    *path_end = '\0';

    //
    // verify that we know about this binary.
    //
    unsigned N = _jove_foreign_lib_count();
    for (unsigned i = 0; i < N; ++i) {
      const char **pforeign_dso_path_beg;
      for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end =
            &foreign_dso_path_beg[foreign_dso_path_len];

        {
          bool match = true;

          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = path_end - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }

          if (!match)
            continue;
        }

        //
        // we've found a match.
        //
        uintptr_t *const fntbl = _jove_foreign_lib_function_table(i);

        ptrdiff_t curr_bias = __jove_foreign_function_tables_bias[i + 3];
        ptrdiff_t load_bias = min - off;

        bool JustLoaded = __jove_foreign_function_tables[i + 3] == NULL;
        bool Reloaded = !JustLoaded && load_bias != curr_bias;
        const bool Changed = JustLoaded || Reloaded;

        if (Changed) {
          if (unlikely(__jove_opts.Debug.Verbose)) {
            char *s;
            ___buff___(s, 2 * PATH_MAX);
            s[0] = '\0';

            _strcat(s, "[found \"");
            _strcat(s, foreign_dso_path_beg);
            _strcat(s, "\" ");
            if (Reloaded)
              _strcat(s, "now ");
            _strcat(s, "@ 0x");
            {
              char buff[65];
              _uint_to_string(load_bias, buff, 0x10);

              _strcat(s, buff);
            }
            if (Reloaded) {
              _strcat(s, " was @ 0x");
              {
                char buff[65];
                _uint_to_string(curr_bias, buff, 0x10);

                _strcat(s, buff);
              }
            }
            _strcat(s, "]\n");

            _DUMP(s);
          }

          if (Reloaded) {
            //
            // undo our modifications to the function pointers
            //
            for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
              fntbl[FIdx] -= curr_bias;
          }

          for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
            fntbl[FIdx] += load_bias;

          __jove_foreign_function_tables_bias[i + 3] = load_bias;
          if (JustLoaded) {
            __jove_foreign_function_tables[i + 3] = fntbl;
          }
        }

        //
        // determine if given program counter is already regarded as fn
        //
        for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx) {
          if (pc == fntbl[FIdx]) {
            //
            // yep, we know about it.
            //
            _jove_found_dyn_target(BBIdx, i + 3, FIdx);
            _jove_sys_exit_group('f');
            __UNREACHABLE();
          }
        }

        //
        // nope, we don't know about this function
        //
        _jove_recover_foreign_function_at_offset(BBIdx, i + 3,
                                                 (pc - min) + off);
        _UNREACHABLE();
      }
    }

    return; /* we don't know about this binary... */
  }
}

void _jove_recover_anonymous_foreign_binary(uintptr_t pc) {
  _VERBOSE_DUMP_FUNC();

  char *wine_stderr_path = _getenv("WINEDEBUGLOG");
  if (!wine_stderr_path)
    return;

  {
    char s[512];
    s[0] = '\0';

    _strcat(s, "_jove_recover_anonymous_binary: 0x");
    {
      char buff[65];
      _uint_to_string(pc, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");
    _DUMP(s);
  }

  char *beg;
  ___buff___(beg, JOVE_LARGE_BUFF_SIZE);
  unsigned n =
      _jove_read_pseudo_file(wine_stderr_path, beg, JOVE_LARGE_BUFF_SIZE);

  char *line;
  char *eol;
  for_each_str_eos_delim_know_end(line, eol, '\n', beg, n) {
    unsigned left = eol - line;
    const char *needle1 = ":trace:module:map_image_into_view mapping ";
    char *map_image_into_view = _memmem(line, left, needle1, _strlen(needle1));
    if (!map_image_into_view)
      continue;

    char *path_beg = map_image_into_view + _strlen(needle1);

    char *p = map_image_into_view; /* space */
    left = eol - p;

    // const char *needle2 = "section .text at ";
    const char *needle2 = " section ";

    char *section = _memmem(p, left, needle2, _strlen(needle2));
    if (!section)
      continue;

    char *const path_end = section;

    char *const sectnm_beg = section + _strlen(needle2);
    char *const sectnm_end = _memchr(sectnm_beg, ' ', eol - sectnm_beg);
    _ASSERT(sectnm_end);

    p = sectnm_end;
    _ASSERT(p[0] == ' ' &&
            p[1] == 'a' &&
            p[2] == 't' &&
            p[3] == ' ' &&
            p[4] == '0' &&
            p[5] == 'x');

    char *const min_beg = p + _strlen(" at 0x");
    char *const min_end = _memchr(min_beg, ' ', eol - min_beg);
    _ASSERT(min_end);

    uint64_t min = _u64ofhexstr(min_beg, min_end);

    char *const off_beg = min_end + _strlen(" off ");
    char *const off_end = _memchr(off_beg, ' ', eol - off_beg);
    _ASSERT(off_end);

    uint64_t off = _u64ofhexstr(off_beg, off_end);

    char *const size_beg = off_end + _strlen("size  ");
    char *const size_end = _memchr(size_beg, ' ', eol - size_beg);
    _ASSERT(size_end);

    uint64_t size = _u64ofhexstr(size_beg, size_end);

    const bool Found = pc >= min && pc < min + size;
    if (!Found)
      continue;
    //
    // we've identified the mapping from WINEDEBUGLOG.
    //
    *path_end = '\0';

#if 1
    //
    // sanity check: we should not already know about this binary
    //
    unsigned N = _jove_foreign_lib_count();
    for (unsigned i = 0; i < N; ++i) {
      const char **pforeign_dso_path_beg;
      for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end =
            &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = path_end - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
          if (!match)
            continue;
        }

        if (match) {
          _UNREACHABLE("foreign binary already known!");
        }
      }
    }
#endif

    _jove_recover_foreign_binary_with_path(path_beg);
  }
}

#endif
