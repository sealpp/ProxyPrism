/* Minimal config.h for vendored libmnl / libnetfilter_queue.
   These libraries normally generate this via autotools; we only need
   the visibility define (everything else has fallbacks in the headers).

   This file lives in the main repo (contrib/config.h) and is found by
   the nf sources' `#include "config.h"` via the contrib include directory
   added by CMake, so submodule contents are never modified. */
#ifndef VENDOR_CONFIG_H
#define VENDOR_CONFIG_H

#define HAVE_DLFCN_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_MEMORY_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_VISIBILITY_HIDDEN 1
#define STDC_HEADERS 1

#define PACKAGE "vendor-nf"
#define PACKAGE_VERSION "1.0"
#define VERSION "1.0"

#endif
