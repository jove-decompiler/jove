#include "except.h"
#include "term.h"
#include "ansi.h"

#include <boost/format.hpp>
#include <boost/archive/archive_exception.hpp>
#include <boost/interprocess/exceptions.hpp>
#include <boost/stacktrace.hpp>
#include <boost/stacktrace/this_thread.hpp>

namespace jove {

typedef boost::format fmt;

bool handle_exceptions(std::function<void(void)> f, std::string &msg) {
  const bool st = smartterm;

  auto initialize_error_message = [=](std::string &msg) -> void {
    msg.append(st ? __ANSI_BOLD_RED : "");
    msg.append("ERROR");
    msg.append(st ? __ANSI_NORMAL_COLOR : "");
    msg.append(": ");
  };

  auto initialize_bug_message = [=](std::string &msg) -> void {
    msg.append(st ? __ANSI_BOLD_RED : "");
    msg.append("BUG");
    msg.append(st ? __ANSI_NORMAL_COLOR : "");
    msg.append(": ");
  };

  msg.clear();
  try {
    f();
    return false;
  } catch (const boost::interprocess::bad_alloc &) {
    initialize_error_message(msg);
    msg.append(
        "exhausted all available memory for .jv. try removing ~/.jv.* and "
        "setting the JVSIZE environment variable to something larger than "
        "the default (e.g. JVSIZE=8G jove init /path/to/program)");
  } catch (const boost::interprocess::lock_exception &) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    initialize_bug_message(msg);
    msg.append("(locking)\n");
    msg.append(boost::stacktrace::to_string(trace));
  } catch (const boost::archive::archive_exception &) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    initialize_bug_message(msg);
    msg.append("(serialization)\n");
    msg.append(boost::stacktrace::to_string(trace));
  } catch (const jove::assertion_failure_base &x) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    msg = (fmt(
      "==================================================\n"
      "%sJOVE ASSERTION FAILURE%s %s%s%s\n%s"
      "==================================================\n")
      % (st ? __ANSI_BOLD_RED : "")
      % (st ? __ANSI_NORMAL_COLOR : "")
      % (st ? __ANSI_YELLOW : "")
      % x.what()
      % (st ? __ANSI_NORMAL_COLOR : "")
      % boost::stacktrace::to_string(trace)).str();
  } catch (const std::exception &x) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    msg = (fmt(
      "%s%s%s\n%s")
      % (st ? __ANSI_BOLD_RED : "")
      % x.what()
      % (st ? __ANSI_NORMAL_COLOR : "")
      % boost::stacktrace::to_string(trace)).str();
  } catch (...) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    initialize_error_message(msg);
    msg = (fmt(
      "exception was thrown!\n%s") % boost::stacktrace::to_string(trace)).str();
  }

  return true;
}

}
