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

#include "crypto_encryption.h"
#include "crypto_publickey.h"

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

// Datatype for an active encrypted session with an AP
typedef struct {
    int active; 
    byte key[SHARED_KEY_SIZE];
    word32 send_counter;
    word32 receive_counter;
} ap_session;

typedef struct {
    byte iv[CHACHA_IV_SIZE];
    byte tag[CHACHA_TAG_SIZE];
    word32 counter;
    int error_code;
    uint8_t length; 
} message_auth;

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

ap_session session;

// Testing global variable for info level messages during POST_BOOT
int booted = 0;

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
    byte send_buf[len];
    bzero(send_buf, sizeof(send_buf));

    message_auth auth;
    auth.error_code = 0;

    if (session.active != 1) {
        print_debug("Session is not active!");
        // return;
        auth.error_code = -1; 
    }

    // IV 
    byte iv[CHACHA_IV_SIZE];
    wc_GenerateSeed(NULL, iv, CHACHA_IV_SIZE); // Initialize IV value using MXC TRNG 

    // Tag 
    byte tag[CHACHA_TAG_SIZE];
    bzero(tag, CHACHA_TAG_SIZE);

    // Store IV
    memcpy(auth.iv, iv, CHACHA_IV_SIZE);

    session.send_counter++;
    auth.counter = session.send_counter;
    auth.length = len;

    // Encrypt data
    int ret = encrypt((byte* ) buffer, len, send_buf, session.key, iv, (byte *) &(auth.counter), sizeof(auth.counter), tag); 
    if (ret != 0) {
        print_debug("Failed to encrypt message: error code %d", ret);
        auth.error_code = -2; 
    }

    // Store tag
    memcpy(auth.tag, tag, sizeof(tag));

    // Send auth before
    send_packet_and_ack(sizeof(auth), (byte *)&auth);

    // Send encrypted data
    send_packet_and_ack(len, send_buf);

    return;
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
    byte data_buf[MAX_I2C_MESSAGE_LEN-1];
    byte auth_buf[MAX_I2C_MESSAGE_LEN-1];

    if (session.active != 1) {
        print_debug("Session not active!");
        return -1;
    }

    int ret = wait_and_receive_packet(data_buf);
    if (ret < SUCCESS_RETURN) {
        print_debug("Error polling for first packet");
        return ret;
    }

    // Send a continue packet to avoid error
    // with two successive receives

    char continue_msg[] = "continue";
    send_packet_and_ack(sizeof(continue_msg), continue_msg);

    ret = wait_and_receive_packet(auth_buf);
    if (ret < SUCCESS_RETURN) {
        print_debug("Error polling for second packet");
        return ret;
    }

    char received_msg[] = "received";
    send_packet_and_ack(sizeof(received_msg), received_msg);

    message_auth auth;
    memcpy(&auth, auth_buf, sizeof(auth));

    if (auth.counter <= session.receive_counter) {
        print_debug("Error! counter was less than receive counter");
        return ERROR_RETURN;
    }

    ret = decrypt((byte* ) buffer, auth.length, data_buf, session.key, auth.iv, (byte *) &(auth.counter), sizeof(auth.counter), auth.tag); 
    if (ret != 0) {
        print_debug("Error decrypting message");
        return ERROR_RETURN;
    }

    session.receive_counter = auth.counter;
    return auth.length;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Do a handshake with the AP
int do_handshake(byte* hello_buffer) {
    WC_RNG rng;
    wc_InitRng(&rng);

    int ret;

    // Copying msg from receive buffer
    signed_hello_with_cert ap_hello;
    memcpy(&ap_hello, hello_buffer, sizeof(ap_hello));

    // Creating component's hello here first to initialize its DH key
    curve25519_key comp_dh_key;
    print_debug("Creating hello for component");
    signed_hello_with_cert comp_hello;
    ret = create_hello(&comp_hello, 0, &comp_dh_key);

    // Component verifies hello and derives its shared key

    byte comp_shared_key[SHARED_KEY_SIZE];
    word32 comp_shared_key_size = SHARED_KEY_SIZE;

    // This is the AP's public key as parsed by the component from its hello
    // Saved for verifying challenge response signature later
    ed25519_key loaded_ap_pubkey;
    wc_ed25519_init(&loaded_ap_pubkey);

    ret = verify_hello(&ap_hello, comp_shared_key, &comp_shared_key_size,
                       &comp_dh_key, AP_TAG, &loaded_ap_pubkey);
    if (ret != 0)
    {
        print_debug("Failed to verify ap hello");
        return -1;
    }

    // Component signs challenge for its response hello

    ed25519_key comp_key;
    ret = load_comp_private_key(&comp_key);
    if (ret != 0)
    {
        print_debug("Error loading component key: %d", ret);
        return -1;
    }

    print_debug("Component signing AP dh key as challenge");

    byte comp_chal_sig_out[ED25519_SIG_SIZE];
    word32 comp_chal_sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(ap_hello.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                    comp_chal_sig_out, &comp_chal_sig_sz, &comp_key);
    if (ret != 0)
    {
        print_debug("Error signing AP DH pubkey with component key: %d", ret);
        return -1;
    }

    print_debug("Creating response signature struct");

    signed_chal comp_sc;

    memset(comp_sc.chal_sig, 0, ED25519_SIG_SIZE);
    memcpy(comp_sc.chal_sig, comp_chal_sig_out, comp_chal_sig_sz);
    comp_sc.chal_sig_size = comp_chal_sig_sz;

    // Send both comp_hello and comp_sc in succession
    memcpy(transmit_buffer, &comp_hello, sizeof(comp_hello));
    send_packet_and_ack((uint8_t)sizeof(comp_hello), transmit_buffer);

    memcpy(transmit_buffer, &comp_sc, sizeof(comp_sc));
    send_packet_and_ack((uint8_t)sizeof(comp_sc), transmit_buffer);

    // Wait for AP response - signed challenge of component
    wait_and_receive_packet(receive_buffer);

    signed_chal ap_sc;
    memcpy(&ap_sc, receive_buffer, sizeof(ap_sc));

    print_debug("Component verifying signed challenge from AP");

    ret = verify_data_signature((byte *)&(comp_hello.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                                ap_sc.chal_sig, ap_sc.chal_sig_size,
                                &loaded_ap_pubkey);
    if (ret != 0)
    {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Component successfully verified AP challenge signature");
    
    // Send done message to complete handshake 
    print_debug("Sending done message");

    char done[] = "done";
    bzero(transmit_buffer, MAX_I2C_MESSAGE_LEN);
    memcpy(transmit_buffer, done, sizeof(done));
    send_packet_and_ack((uint8_t) sizeof(done), transmit_buffer);

    // Create session
    session.active = 1;
    memcpy(session.key, comp_shared_key, SHARED_KEY_SIZE);
    session.send_counter = 0;
    session.receive_counter = 0;

    print_debug("Leaving do_handshake()");

    return 0;
}

// Example boot sequence
// Your design does not need to change this
void boot() {
    booted = 1;

    print_debug("Testing secure receive on component");
    // TEST - check secure receive for component
    bzero(receive_buffer, MAX_I2C_MESSAGE_LEN);
    secure_receive(receive_buffer);
    char expected[] = "hellofromap";

    if (strncmp((unsigned char *) receive_buffer, expected, sizeof(expected)) != 0) {
        print_error("Secure receive on component failed");
        return; 
    }

    char comptest[] = "hellofromcomp";
    secure_send(comptest, sizeof(comptest));

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
    // The AP sent a boot command
    command_message* command = (command_message*) receive_buffer;

    // Do a handshake to verify the boot
    int ret = do_handshake(command->params);
    if (ret != 0) {
        print_error("Error doing handshake!");
        return; 
    } 

    // Securely send the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    secure_send(transmit_buffer, len);

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
    command_message* command = (command_message*) receive_buffer;

    int ret = do_handshake(command->params);
    if (ret != 0) {
        print_error("Error doing handshake!");
        return -1; 
    } 

    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;

    secure_send(transmit_buffer, len);
    
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
