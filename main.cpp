/*
 *  Hello world example of using the hashing functions of Mbed TLS
 *
 *  Copyright (C) 2016, Arm Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * This program illustrates various ways of hashing a buffer.
 * You normally need only one of these two includes.
 */
#include "mbed.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/md.h"     /* generic interface */

#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls/platform.h"

#include <string.h>

#define ASCII_CARIAGE_RETURN	0x0D

static void print_hex(const unsigned char buf[], size_t len)
{
    for (size_t i = 0; i < len; i++)
        mbedtls_printf("%02x", buf[i]);

    mbedtls_printf("\n");
}


int main() {
    int exit_code = MBEDTLS_EXIT_FAILURE, i = 0;

    if((exit_code = mbedtls_platform_setup(NULL)) != 0) {
        printf("Platform initialization failed with error %d\n", exit_code);
        return MBEDTLS_EXIT_FAILURE;
    }

    unsigned char output1[32]; /* SHA-256 outputs 32 bytes */
	unsigned char userMsg[100];
	uint8_t strLen = 0;
	
	Serial pc(UART_TX, UART_RX);
	
	pc.printf("AES Demonstration - mbedOS \r\n");
	
	for(;;)
	{
		pc.printf("Enter the string : \r\n");
		i = 0;
		
		do{
			userMsg[i] = pc.getc();
			
		}while(userMsg[i++] != ASCII_CARIAGE_RETURN);
		
		//strLen = scanf("%s", userMsg);

		/* 0 here means use the full SHA-256, not the SHA-224 variant */
		mbedtls_sha256(userMsg, i, output1, 0);

		print_hex(output1, sizeof output1);

		mbedtls_printf("\nDONE\n");
	}

    return exit_code;
}
