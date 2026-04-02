#pragma once

#include "types.h"

typedef uint64_t ticks_t;

ticks_t now();
uint64_t clock_scale();

void sleep_ms(time_ms_t time);
void sleep_s(time_s_t time);
