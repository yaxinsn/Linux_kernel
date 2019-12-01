/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.35   2015/11/11
 */

#include "internal.h"
#include "probe.h"

#include "../scheme.h"
#if defined(KERNEL_NO_CONFIG_SECURITY)
#include "lsm-2.6.0-no-sec.c"
#else
#include "lsm-2.6.0-sec.c"
#endif
 
