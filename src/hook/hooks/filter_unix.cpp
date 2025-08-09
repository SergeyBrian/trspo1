#include "filter.h"

#include <iostream>

#include "hook/manager/manager.h"

namespace hooks::filter {
static std::string hidden_str;
void SetHideStrig(const std::string &s) { hidden_str = s; }
}  // namespace hooks::filter
