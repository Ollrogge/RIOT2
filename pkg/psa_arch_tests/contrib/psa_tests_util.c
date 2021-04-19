#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fmt.h"
#include "periph/flashpage.h"
#include "stdio_uart.h"

#define SIM_FLASHSIZE       (128)
#define LINE_LEN            (16)
#define PRINT_BUFF_SIZE     (100)

/* When writing raw bytes on flash, data must be correctly aligned. */
#define ALIGNMENT_ATTR __attribute__((aligned(FLASHPAGE_WRITE_BLOCK_ALIGNMENT)))

void riot_uart_write(const char *str, int32_t data) {
    int len = fmt_strlen(str);
    int datalen = 0;
    char output[PRINT_BUFF_SIZE];
    int pos = 0;

    for (int i = 0; i < len; i++) {
        if (str[i] == '%') {
            switch (str[i+1]) {
                case 'd':
                case 'i':
                    datalen = fmt_u32_dec(output+pos, data);
                    pos += datalen;
                    i++;
                    break;
                case 'x':
                    datalen = fmt_u32_hex(output+pos, data);
                    pos += datalen;
                    i++;
                    break;
            }
        }
        else {
            output[pos++] = str[i];
            if (pos >= PRINT_BUFF_SIZE) {
                stdio_write(output, PRINT_BUFF_SIZE);
                pos = 0;
            }
        }
    }

    if (pos) {
        stdio_write(output, pos);
    }
}

/* ----------------------------------------------------------------- */
/* Some PSA Architecture test cases reboot or crash the device or application on purpose. In order to be able to pick up where it left off, the application needs to write some flags and the previous test ID into non volatile memory. Since those tests are not part of the PSA Developer API tests and the flags don't have to be persistent at this point I simulate non volatile memory with an array. */

static uint8_t flash_simulation[SIM_FLASHSIZE];

void riot_nvmem_read(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    memcpy(buffer, flash_simulation+offset, size);
}

void riot_nvmem_write(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    memcpy(flash_simulation+offset, buffer, size);
}
