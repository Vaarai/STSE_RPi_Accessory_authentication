#ifndef CRC16_H
#define CRC16_H

#include <stdint.h>

void crc16_Init (void);
uint16_t crc16_Calculate (uint8_t* address, uint16_t length);
uint16_t crc16_Accumulate (uint8_t* address, uint16_t length);

#endif /* CRC16_H */
