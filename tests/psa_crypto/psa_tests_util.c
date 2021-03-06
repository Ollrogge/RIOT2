#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fmt.h"
#include "stdio_uart.h"

#define PRINT_BUFF_SIZE (32)

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