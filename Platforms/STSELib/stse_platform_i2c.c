#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

#include "core/stse_platform.h"

int file_desc_i2c_interface;

static PLAT_UI8* pI2c_buffer;
static PLAT_UI16 i2c_frame_size;
static volatile PLAT_UI16 i2c_frame_offset;

stse_ReturnCode_t stse_platform_i2c_init (PLAT_UI8 busID)
{
	(void) busID;
	char *filename = (char*)"/dev/i2c-1";
	if ((file_desc_i2c_interface = open(filename, O_RDWR)) < 0)
	{
		return STSE_PLATFORM_SERVICES_INIT_ERROR;
	}
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_wake (PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_i2c_send_start (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI16 FrameLength)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	/* - Allocate Communication buffer */
	pI2c_buffer = malloc(FrameLength);

	/* - Check buffer overflow */
	if (pI2c_buffer == NULL)
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	i2c_frame_size = FrameLength;
	i2c_frame_offset = 0;

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	if(data_size != 0)
	{
		if(pData == NULL)
		{
			memset((pI2c_buffer + i2c_frame_offset),0x00,data_size);
		}
		else
		{
			memcpy((pI2c_buffer + i2c_frame_offset),pData,data_size);
		}
		i2c_frame_offset += data_size;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	stse_ReturnCode_t ret;

	ret =  stse_platform_i2c_send_continue (
			busID,
			devAddr,
			speed,
			pData,
			data_size);

	if (ret != STSE_OK)
	{
		return ret;
	}

	if (ioctl(file_desc_i2c_interface, I2C_SLAVE, devAddr) < 0)
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	if (write(file_desc_i2c_interface, pI2c_buffer, i2c_frame_size) != i2c_frame_size)
	{
		return STSE_PLATFORM_BUS_ACK_ERROR;
	}

	/* - Free memory allocated to i2c buffer*/
	free(pI2c_buffer);

	return ret;
}

stse_ReturnCode_t stse_platform_i2c_receive_start (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI16 frameLength)
{
	(void)busID;

	/* - Store response Length */
	i2c_frame_size = frameLength;

	/* - Allocate Communication buffer */
	pI2c_buffer = malloc(frameLength);

	/* - Check buffer overflow */
	if (pI2c_buffer == NULL)
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	if (ioctl(file_desc_i2c_interface, I2C_SLAVE, devAddr) < 0)
	{
		return STSE_PLATFORM_BUFFER_ERR;
	}

	/* - Read full Frame */
	if (read(file_desc_i2c_interface, pI2c_buffer, i2c_frame_size) != i2c_frame_size)
	{
		return STSE_PLATFORM_BUS_ACK_ERROR;
	}

	/* - Reset read offset */
	i2c_frame_offset = 0;

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_continue (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	(void)busID;
	(void)devAddr;
	(void)speed;

	if (pData != NULL)
	{

		/* Check read overflow */
		if((i2c_frame_size - i2c_frame_offset) < data_size)
		{
			return STSE_PLATFORM_BUFFER_ERR;
		}

		/* Copy buffer content */
		memcpy(pData,(pI2c_buffer + i2c_frame_offset),data_size);
	}

	i2c_frame_offset += data_size;

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop (
		PLAT_UI8 busID,
		PLAT_UI8 devAddr,
		PLAT_UI16 speed,
		PLAT_UI8* pData,
		PLAT_UI16 data_size)
{
	/*- Copy last element*/
	stse_platform_i2c_receive_continue(busID, devAddr, speed, pData, data_size);

	i2c_frame_offset = 0;

	/*- Free i2c buffer*/
	free(pI2c_buffer);
	return (STSE_OK);
}
