#include <stdio.h>
#include <string.h>

#include "stselib.h"

int main() {
	stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
	stse_Handler_t stse_handler;

	uint8_t echo_tx_buffer[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	uint8_t echo_rx_buffer[16];

	/* ## Initialize STSE device handler */
	stse_ret = stse_set_default_handler_value(&stse_handler);
	stse_handler.device_type = STSAFE_A120;
	stse_ret = stse_init(&stse_handler);
	if (stse_ret != STSE_OK)
	{
		printf("\n\r ## stse_init ERROR : 0x%04X\n\r",stse_ret);
		return 1;
	}
	printf("\n\r # stse_init OK\n\r");

	printf("    echo_tx_buffer: \n\r    ");
	for(uint16_t i=0;i<16;i++)
	{
		printf(" 0x%02X",echo_tx_buffer[i]);
	}
	printf(" \n\r ");

	stse_ret = stse_device_echo(
		&stse_handler,
		echo_tx_buffer,
		echo_rx_buffer,
		16);
	if (stse_ret != STSE_OK)
	{
		printf(" ## stse_device_echo ERROR : 0x%04X\n\r",stse_ret);
		return 1;
	}

	printf("    echo_rx_buffer: \n\r    ");
	for(uint16_t i=0;i<16;i++)
	{
		printf(" 0x%02X",echo_rx_buffer[i]);
	}
	printf(" \n\r ");

	return 0;
}
