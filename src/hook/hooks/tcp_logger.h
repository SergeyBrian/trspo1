#ifndef H_HOOK_HOOKS_LOGGER_H
#define H_HOOK_HOOKS_LOGGER_H

#include "common/include/io.h"

namespace hooks::tcp_logger {
void *Logger(const char *func_name, io::IStream *s);
}

#endif
