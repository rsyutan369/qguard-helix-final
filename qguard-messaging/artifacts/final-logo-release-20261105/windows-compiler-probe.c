#include <stdint.h>
#include <stdlib.h>
#include "compat.h"
_Static_assert(sizeof(void*) == 8, "Windows x64 required");
int qguard_compiler_probe(void) { return (int)sizeof(uint64_t); }
