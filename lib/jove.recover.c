//
// this code is paired with tools/jove-recover.cpp
//

_HIDDEN void _jove_recover_dyn_target(uint32_t CallerBBIdx,
                                      uintptr_t CalleeAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  uint32_t CallerBIdx = _jove_binary_index();

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
    struct _jove_function_info_t *x;

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
    struct _jove_function_info_t *finfo;

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
    uintptr_t _m _CLEANUP(_jove_free_large_buffp) = _jove_alloc_large_buff();
    char *const maps = (char *)_m;

    unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, JOVE_LARGE_BUFF_SIZE);
    maps[n] = '\0';

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
        const char *foreign_dso_path_beg = _jove_foreign_lib_path(i);
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
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          break;
        }
      }
    }
  }

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    uintptr_t _m _CLEANUP(_jove_free_large_buffp) = _jove_alloc_large_buff();
    char *const maps = (char *)_m;

    unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, JOVE_LARGE_BUFF_SIZE);
    maps[n] = '\0';

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
        const char *foreign_dso_path_beg = _jove_foreign_lib_path(i);
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

  return; /* not found */

found:
  if (!recover_fifo_path) {
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
      _uint_to_string(Callee.BIdx, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, ",");
    {
      char buff[65];
      _uint_to_string(Callee.FIdx, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

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
        *((uint32_t *)&buff[sizeof(char) + 0 * sizeof(uint32_t)]) = CallerBIdx;
        *((uint32_t *)&buff[sizeof(char) + 1 * sizeof(uint32_t)]) = CallerBBIdx;
        *((uint32_t *)&buff[sizeof(char) + 2 * sizeof(uint32_t)]) = Callee.BIdx;
        *((uint32_t *)&buff[sizeof(char) + 3 * sizeof(uint32_t)]) = Callee.FIdx;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_function(uint32_t IndCallBBIdx,
                            uintptr_t FuncAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndCall;

  IndCall.BIdx = _jove_binary_index();
  IndCall.BBIdx = IndCallBBIdx;

  struct {
    uint32_t BIdx;
    uintptr_t FileAddr;
  } Callee;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *Entry = __jove_sections_tables[BIdx];
    if (likely(!Entry))
      continue;

    struct {
      uintptr_t Beg;
      uintptr_t End;
    } SectionsGlobal;

    uintptr_t SectsStartFileAddr;

    SectionsGlobal.Beg = Entry[0];
    SectionsGlobal.End = Entry[1];
    SectsStartFileAddr = Entry[2];

    if (FuncAddr >= SectionsGlobal.Beg && FuncAddr < SectionsGlobal.End) {
      Callee.BIdx = BIdx;
      Callee.FileAddr = (FuncAddr - SectionsGlobal.Beg) + SectsStartFileAddr;
      goto found;
    }
  }

  return; /* not found */

found:
  if (!recover_fifo_path) {
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
      _uint_to_string(Callee.FileAddr, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

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
        *((uint32_t *)&buff[sizeof(char) + 0 * sizeof(uint32_t)]) = IndCall.BIdx;
        *((uint32_t *)&buff[sizeof(char) + 1 * sizeof(uint32_t)]) = IndCall.BBIdx;
        *((uint32_t *)&buff[sizeof(char) + 2 * sizeof(uint32_t)]) = Callee.BIdx;
        *((uintptr_t*)&buff[sizeof(char) + 3 * sizeof(uint32_t)]) = Callee.FileAddr;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

_HIDDEN void _jove_recover_basic_block(uint32_t IndBrBBIdx,
                                       uintptr_t BBAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndBr;

  struct {
    uintptr_t Beg;
    uintptr_t End;
  } SectionsGlobal;

  uintptr_t SectsStartFileAddr;

  IndBr.BIdx = _jove_binary_index();
  IndBr.BBIdx = IndBrBBIdx;

  SectionsGlobal.Beg = _jove_sections_global_beg_addr();
  SectionsGlobal.End = _jove_sections_global_end_addr();
  SectsStartFileAddr = _jove_sections_start_file_addr();

  if (!(BBAddr >= SectionsGlobal.Beg && BBAddr < SectionsGlobal.End))
    return; /* not found */

  uintptr_t FileAddr = (BBAddr - SectionsGlobal.Beg) + SectsStartFileAddr;

found:
  if (!recover_fifo_path) {
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
      _uint_to_string(FileAddr, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));

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
        *((uint32_t *)&buff[sizeof(char) + 0 * sizeof(uint32_t)]) = IndBr.BIdx;
        *((uint32_t *)&buff[sizeof(char) + 1 * sizeof(uint32_t)]) = IndBr.BBIdx;
        *((uintptr_t*)&buff[sizeof(char) + 2 * sizeof(uint32_t)]) = FileAddr;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

_HIDDEN void _jove_recover_returned(uint32_t CallerBBIdx) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } Call;

  Call.BIdx = _jove_binary_index();
  Call.BBIdx = CallerBBIdx;

found:
  if (!recover_fifo_path) {
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
        *((uint32_t *)&buff[sizeof(char) + 0 * sizeof(uint32_t)]) = Call.BIdx;
        *((uint32_t *)&buff[sizeof(char) + 1 * sizeof(uint32_t)]) = Call.BBIdx;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

_HIDDEN void _jove_recover_ABI(uint32_t FIdx) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } NewABI;

  NewABI.BIdx = _jove_binary_index();
  NewABI.FIdx = FIdx;

found:
  if (!recover_fifo_path) {
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
        *((uint32_t *)&buff[sizeof(char) + 0 * sizeof(uint32_t)]) = NewABI.BIdx;
        *((uint32_t *)&buff[sizeof(char) + 1 * sizeof(uint32_t)]) = NewABI.FIdx;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
    }
  }
}
