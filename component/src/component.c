/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#include "crypto_test.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
int process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    send_packet_and_ack(len, buffer); 
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    return wait_and_receive_packet(buffer);
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

int process_attest() {
    WC_RNG rng;
    wc_InitRng(&rng);

    int ret;
    
    // Copying msg from receive buffer
    signed_hello_with_cert msg;
    memcpy(&msg, receive_buffer, sizeof(msg));

    // Creating component's hello here first to initialize its DH key
    ecc_key comp_dh_key;
    print_debug("Creating hello for component");

    signed_hello_with_cert resp;
    ret = create_hello(&resp, 0, &comp_dh_key);
    if (ret != 0) {
        print_debug("Failed to create component hello!");
    }

    // Component verifies hello and derives its shared key
    byte comp_shared_key[SHARED_KEY_SIZE];
    word32 comp_shared_key_size = SHARED_KEY_SIZE;

    // This is the AP's public key as parsed by the component from its hello
    // Saved for verifying challenge response signature later
    ecc_key ap_pubkey;
    wc_ecc_init(&ap_pubkey);

    ret = verify_hello(&msg, comp_shared_key, &comp_shared_key_size,
                       &comp_dh_key, AP_TAG, &ap_pubkey);
    if (ret != 0) {
        print_debug("Failed to verify ap hello");
        return -1;
    }

    // Component signs challenge for its response hello
    signed_chal resp_chal;

    ecc_key comp_key;
    ret = load_comp_private_key(&comp_key);
    if (ret != 0) {
        print_debug("Error loading component key: %d", ret);
        return -1;
    }

    print_debug("Component signing AP dh key as challenge");

    byte comp_chal_sig_out[ECC_SIG_SIZE];
    word32 comp_chal_sig_sz = ECC_SIG_SIZE;

    ret = sign_data((byte *)&(msg.sh.hi.dh_pubkey), COMPR_KEY_SIZE,
                    comp_chal_sig_out, &comp_chal_sig_sz, &comp_key, &rng);
    if (ret != 0) {
        print_debug("Error signing AP DH pubkey with component key: %d", ret);
        return -1;
    }

    print_debug("Creating response signature struct");

    memset(resp_chal.chal_sig, 0, ECC_SIG_SIZE);
    memcpy(resp_chal.chal_sig, comp_chal_sig_out, comp_chal_sig_sz);
    resp_chal.chal_sig_size = comp_chal_sig_sz;

    // Send both resp and resp_chal in succession
    memcpy(transmit_buffer, &resp, sizeof(resp));
    send_packet_and_ack((uint8_t) sizeof(resp), transmit_buffer);
    
    memcpy(transmit_buffer, &resp_chal, sizeof(resp_chal));
    send_packet_and_ack((uint8_t) sizeof(resp_chal), transmit_buffer);

    // Wait for AP response - signed challenge of component
    wait_and_receive_packet(receive_buffer);

    signed_chal ap_sc;
    memcpy(&ap_sc, receive_buffer, sizeof(ap_sc));

    print_debug("Component verifying signed challenge from AP");

    ret = verify_data_signature((byte *) &(resp.sh.hi.dh_pubkey), COMPR_KEY_SIZE,
                                ap_sc.chal_sig, ap_sc.chal_sig_size,
                                &ap_pubkey);
    if (ret != 0) {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Component successfully verified AP challenge signature");

    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    send_packet_and_ack(len, transmit_buffer);
    
    return 0;
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}
