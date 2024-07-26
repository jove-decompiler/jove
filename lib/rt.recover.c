void _jove_recover_function(uintptr_t FuncAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndCall;

  IndCall.BIdx  = 0xffffffff;
  IndCall.BBIdx = 0xffffffff;

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
      _uint_to_string(Callee.Addr, buff, 10);

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
        *((uintptr_t*)&buff[sizeof(char) + 3 * sizeof(uint32_t)]) = Callee.Addr;

        if (_jove_sys_write(recover_fd, &buff[0], sizeof(buff)) != sizeof(buff))
          _UNREACHABLE();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

