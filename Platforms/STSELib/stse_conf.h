#ifndef STSE_CONF_H
#define STSE_CONF_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define PLAT_UI8 uint8_t
#define PLAT_UI16 uint16_t
#define PLAT_UI32 uint32_t
#define PLAT_UI64 uint64_t
#define PLAT_I8 int8_t
#define PLAT_I16 int16_t
#define PLAT_I32 int32_t
#define PLAT_PACKED_STRUCT __attribute__((packed, aligned(1)))
#define __WEAK __attribute__((weak))

#define STSE_USE_RSP_POLLING
#define STSE_MAX_POLLING_RETRY 			100
#define STSE_FIRST_POLLING_INTERVAL		10
#define STSE_POLLING_RETRY_INTERVAL		10

#endif /* STSE_CONF_H */