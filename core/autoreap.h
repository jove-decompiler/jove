#pragma once

namespace jove {

//
// automatically reap children, by ignoring SIGCHLD.
//
// NOTE: this has the effect of disabling the pidfd_open(2) guarantee that no
// PID's are recycled, following a fork(2).
// 
//
void AutomaticallyReap(void);

}
