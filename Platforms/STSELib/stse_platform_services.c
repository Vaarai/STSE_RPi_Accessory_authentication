#include <stdlib.h>
#include <unistd.h>

#include "Drivers/crc16/crc16.h"
#include "core/stse_platform.h"

stse_ReturnCode_t stse_services_platform_init (void)
{
	/* Initialize platform Drivers used by PAL */
	crc16_Init();
	return STSE_OK;
}

PLAT_UI16 stse_platform_Crc16_Calculate (PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	return crc16_Calculate(pbuffer, length);
}

PLAT_UI16 stse_platform_Crc16_Accumulate (PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	return crc16_Accumulate(pbuffer, length);
}

void stse_platform_Delay_ms (PLAT_UI32 delay_val)
{
	usleep(delay_val*1000);
}

void stse_platform_timeout_ms_start(PLAT_UI16 timeout_val)
{
	/* TODO */
}

PLAT_UI8 stse_platform_timeout_ms_get_status(void)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_power_on (PLAT_UI8 bus , PLAT_UI8 devAddr)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_power_off (PLAT_UI8 bus , PLAT_UI8 devAddr)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}
