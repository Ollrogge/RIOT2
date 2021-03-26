#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fmt.h"
#include "periph/flashpage.h"
#include "stdio_uart.h"

#define SIM_FLASHSIZE       (96)
#define LINE_LEN            (16)
#define PRINT_BUFF_SIZE     (32)
/* When writing raw bytes on flash, data must be correctly aligned. */
#define ALIGNMENT_ATTR __attribute__((aligned(FLASHPAGE_WRITE_BLOCK_ALIGNMENT)))

int first_read = 1;

// struct formatted_buffer_t {
//     size_t pos;
//     uint8_t buf[PRINT_BUFF_SIZE];
// };

void riot_uart_write(const void *str, int32_t data) {
    // (void) data;
    int len = fmt_strlen(str);
    char *input = (char *) str;
    int datalen = 0;
    char output[PRINT_BUFF_SIZE];

    for (int i = 0; i < len; i++) {
        if (input[i] == '%') {
            switch (input[i+1]) {
                case 'd':
                case 'i':
                    datalen = fmt_u32_dec(output, data);
                    output[datalen++] = '\n';
                    break;
                case 'x':
                    datalen += fmt_u32_hex(output, data);
                    output[datalen++] = '\n';
                    break;
            }            
        }
    }

    stdio_write(str, len-3);
    stdio_write(output, datalen);
}

/* ----------------------------------------------------------------- */

// static uint8_t page_read[FLASHPAGE_SIZE] ALIGNMENT_ATTR;
static uint8_t flash_simulation[SIM_FLASHSIZE];

void riot_nvmem_read(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    if (first_read) {
        memset(flash_simulation, 0xFF, SIM_FLASHSIZE);
        first_read = 0;
    }
    memcpy(buffer, flash_simulation+offset, size);
}

void riot_nvmem_write(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    memcpy(flash_simulation+offset, buffer, size);
}

// void riot_nvmem_read(uint32_t base, uint32_t offset, void *buffer, int size)
// {
//     (void) base;
//     if (first_read) {
//         flashpage_erase(100);
//         first_read = 0;
//     }
//     /* Always read and write to flash page 100 (only applies do NRF52840) */
//     uint32_t page = 100;
//     memset(page_read, 0xFF, FLASHPAGE_SIZE);
//     flashpage_read(page, page_read);
//     memcpy(buffer, page_read+offset, size);
//     printf("Read: \n");
//     // memdump(page_read, 100);
// }

// void riot_nvmem_write(uint32_t base, uint32_t offset, void *buffer, int size)
// {
//     (void) base;
//     /* Always read and write to flash page 100 (only applies do NRF52840) */
//     uint32_t page = 100;
//     uint8_t tmp[FLASHPAGE_WRITE_BLOCK_SIZE] = { 0x00 };
//     printf("Write: \n");
//     if ((unsigned int) size < FLASHPAGE_WRITE_BLOCK_SIZE) {
//         for (int i = FLASHPAGE_WRITE_BLOCK_SIZE-1; i >= 0; i--) {
//             tmp[i] = ((uint8_t*)buffer)[i];
//         }
//         flashpage_write(flashpage_addr(page)+offset, tmp, FLASHPAGE_WRITE_BLOCK_SIZE);
//     }
//     else {
//         flashpage_write(flashpage_addr(page)+offset, buffer, size);
//     }
//     memset(page_read, 0xFF, FLASHPAGE_SIZE);
//     flashpage_read(page, page_read);
//     memcpy(buffer, page_read+offset, size);
//     printf("Read after write: \n");
//     memdump(page_read, 100);
//     // memdump(page_write, 100);    
// }
