#include "qemutcg.h"

int main(int argc, char** argv) {
  libqemutcg_init();
  libqemutcg_dump_globals();

  return 0;
}
