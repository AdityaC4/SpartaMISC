#include "simple_i2c_controller.h"
#include <stdio.h>

void printReceivedI2CMessage(const uint8_t* message, size_t length) {
    printf("Message: ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02X ", message[i]);  
    }
    //printf("\n"); ///if needed add
}
