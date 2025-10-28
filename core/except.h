#pragma once
#include <string>
#include <functional>

namespace jove {

bool handle_exceptions(std::function<void(void)>, std::string &msg);

}
