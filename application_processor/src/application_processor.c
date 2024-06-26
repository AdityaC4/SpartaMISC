/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "trng.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
#ifdef CRYPTO_EXAMPLE
// Include custom crypto test
#include "crypto_encryption.h"
#include "crypto_publickey.h"
#include "wolfssl/wolfcrypt/random.h"
#endif

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
// Defining two addresses for where we store delay status of PIN and token validation
#define DELAY_FLASH_ADDR_PIN ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (10*MXC_FLASH_PAGE_SIZE))
#define DELAY_FLASH_ADDR_TOKEN ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4*MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Smaller version of flash entry for delay status
typedef struct {
    uint32_t flash_magic;
} smaller_flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

// Datatype for an active encrypted session with a component
typedef struct {
    word32 component_id;
    int active; 
    byte key[SHARED_KEY_SIZE];
    word32 send_counter;
    word32 receive_counter;
} component_session;

// Struct for storing auth tags
typedef struct {
    byte iv[CHACHA_IV_SIZE];
    byte tag[CHACHA_TAG_SIZE];
    word32 counter;
    int error_code;
    uint8_t length; 
} message_auth;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
// Delay status variabels which we read into from flash, or write to flash with
smaller_flash_entry delay_status_pin;
smaller_flash_entry delay_status_token;

// Active sessions with components
component_session sessions[COMPONENT_CNT];

// Testing global variable for info level messages during POST_BOOT
int booted = 0;


/********************************* REFERENCE FLAG **********************************/
// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// NOTE: you're not allowed to do this in your code
// Remove this in your design

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    byte send_buf[len];
    bzero(send_buf, sizeof(send_buf));

    component_session* session = NULL; 
    for (int i = 0; i < COMPONENT_CNT; ++i) {
        if (component_id_to_i2c_addr(sessions[i].component_id) == address) {
            session = &(sessions[i]);
        }
    }
    if (!session) {
        print_error("Could not find a component with matching address!");
        return -1;
    }
    if (session->active != 1) {
        print_error("Session is not active!");
        return -1;
    }

    // IV 
    byte iv[CHACHA_IV_SIZE];
    MXC_TRNG_Init();
    while(MXC_TRNG_HealthTest() == 0){
        print_debug("TRNG health check failed, attack detected, delaying\n");
        MXC_Delay(4500000);
    }
    MXC_TRNG_Shutdown();
    wc_GenerateSeed(NULL, iv, CHACHA_IV_SIZE); // Initialize IV value using MXC TRNG 

    // Tag 
    byte tag[CHACHA_TAG_SIZE];
    bzero(tag, CHACHA_TAG_SIZE);

    message_auth auth;

    // Store IV
    memcpy(auth.iv, iv, CHACHA_IV_SIZE);

    session->send_counter++;
    auth.counter = session->send_counter;
    auth.length = len;
    auth.error_code = 0; 

    // Encrypt data
    int ret = encrypt((byte* ) buffer, len, send_buf, session->key, iv, (byte *) &(auth.counter), sizeof(auth.counter), tag); 
    if (ret != 0) {
        print_error("Failed to encrypt message: error code %d", ret);
    }

    // Store tag
    memcpy(auth.tag, tag, sizeof(tag));

    // Send encrypted data
    ret = send_packet(address, len, send_buf);
    if (ret < SUCCESS_RETURN) {
        print_error("Error sending encrypted packet");
        return ret;
    }

    // if (booted) {
    //     print_info("AP: Sent Packet\n");
    // }

    // Wait for a continue message
    // to avoid error with successive sends from AP
    char continue_buf[MAX_I2C_MESSAGE_LEN - 1];
    char expected[] = "continue";

    ret = poll_and_receive_packet(address, continue_buf);
    if (ret < SUCCESS_RETURN) {
        print_error("Error polling for continue packet");
        return ret;
    }

    if (strncmp(continue_buf, expected, sizeof(expected) != 0)) {
        print_error("Continue packet does not match!");
        return -1;
    }

    // Send IV and authentication data
    ret = send_packet(address, sizeof(auth), (byte *) &auth);
    if (ret < SUCCESS_RETURN) {
        print_error("Error sending authenticated data");
    }

    // Wait for a received message
    char received_buf[MAX_I2C_MESSAGE_LEN - 1];
    char expected2[] = "received";

    ret = poll_and_receive_packet(address, received_buf);
    if (ret < SUCCESS_RETURN) {
        print_error("Error polling for received packet");
        return ret;
    }

    if (strncmp(received_buf, expected2, sizeof(expected2) != 0)) {
        print_error("Received packet does not match!");
        return -1;
    }

    return ret;
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    byte data_buf[MAX_I2C_MESSAGE_LEN-1];
    bzero(data_buf, sizeof(data_buf));

    byte auth_buf[MAX_I2C_MESSAGE_LEN-1];
    bzero(auth_buf, sizeof(auth_buf));

    component_session* session = NULL; 
    for (int i = 0; i < COMPONENT_CNT; ++i) {
        if (component_id_to_i2c_addr(sessions[i].component_id) == address) {
            session = &(sessions[i]);
        }
    }
    if (!session) {
        print_error("Could not find a component with matching address!");
        return -1;
    }
    if (session->active != 1) {
        print_error("Session is not active!");
        return -1;
    }

    int ret = poll_and_receive_packet(address, auth_buf);
    if (ret < SUCCESS_RETURN) {
        print_error("Error polling for second packet");
        return ret;
    }

    message_auth auth;
    memcpy(&auth, auth_buf, sizeof(auth));

    ret = poll_and_receive_packet(address, data_buf);
    if (ret < SUCCESS_RETURN) {
        print_error("Error polling for first packet");
        return ret;
    }

    if (auth.error_code != 0) {
        print_error("Error in auth! Found code %d", auth.error_code);
        return ERROR_RETURN;
    }

    if (auth.counter <= session->receive_counter) {
        print_error("Error! counter was less than receive counter");
        return ERROR_RETURN;
    }

    ret = decrypt((byte* ) buffer, auth.length, data_buf, session->key, auth.iv, (byte *) &(auth.counter), sizeof(auth.counter), auth.tag); 
    if (ret != 0) {
        print_error("Error decrypting message");
        return ERROR_RETURN;
    }

    session->receive_counter = auth.counter;
    return auth.length;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Compare two buffers with no time leakage
int secure_cmp(char *buf, char *passcode, int len) {
    // Similar to strcmp, if it's sucessful it returns 0
    int success = 0;

    for (int i = 0; i < len; i++) {
        if (buf[i] != passcode[i]) {
            success = 1;
        }
    }
    return success;
}

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
        // Erases our delay status flash addresses in case they were written to
        // before boot
        flash_simple_erase_page(DELAY_FLASH_ADDR_PIN);
        flash_simple_erase_page(DELAY_FLASH_ADDR_TOKEN);
    }
    
    // Initialize board link interface
    board_link_init();

    // Initialize sessions array
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        component_session* session = &(sessions[i]);
        session->component_id = (word32) flash_status.component_ids[i];
        session->active = 0;
        bzero(session->key, SHARED_KEY_SIZE);
        session->send_counter = 0;
        session->receive_counter = 0;
    }
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    int result = send_packet(addr, sizeof(uint8_t), transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int do_handshake(uint32_t component_id, uint8_t initial_command) {    
    // Start handshake
    print_debug("Doing handshake");

    WC_RNG rng;
    wc_InitRng(&rng);

    int ret;

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    bzero(receive_buffer, sizeof(receive_buffer));

    uint8_t receive_buffer_2[MAX_I2C_MESSAGE_LEN];
    bzero(receive_buffer_2, sizeof(receive_buffer_2));

    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    bzero(transmit_buffer, sizeof(transmit_buffer));

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message *command = (command_message *)transmit_buffer;
    command->opcode = initial_command;

    // Create hello message
    curve25519_key ap_dh_key;
    signed_hello_with_cert ap_hello;

    ret = create_hello(&ap_hello, 1, &ap_dh_key);
    if (ret != 0)
    {
        print_debug("Error creating signed ap hello with cert");
        return -1;
    }
    memcpy(command->params, &ap_hello, sizeof(ap_hello));

    print_debug("Issuing hello attest command...");

    // Send out command along with hello and receive result
    // int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    // if (len == ERROR_RETURN) {
    //     print_error("Could not attest component\n");
    //     return ERROR_RETURN;
    // }

    int result = send_packet(addr, sizeof(uint8_t) + sizeof(ap_hello), transmit_buffer);
    if (result == ERROR_RETURN) {
        print_error("Could not send hello packet to component");
        return ERROR_RETURN;
    }

    // Receive first response
    int len = poll_and_receive_packet(addr, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not receive first response from component");
        return ERROR_RETURN;
    }
    // print_debug("Received first response from component");
    // print_info("%s", receive_buffer);

    print_debug("Received first response, polling for challenge signature...");

    // Immediately after, poll for and receive the challenge signature
    len = poll_and_receive_packet(addr, receive_buffer_2);
    if (len == ERROR_RETURN) {
        print_error("Error in receiving challenge response packet");
        return ERROR_RETURN;
    }

    // The first response packet from component will be the component's hello
    signed_hello_with_cert comp_hello;
    memcpy((byte *)&comp_hello, receive_buffer, sizeof(comp_hello));

    // The second one is the challenge signature
    signed_chal comp_sc;
    memcpy((byte *)&comp_sc, receive_buffer_2, sizeof(comp_sc));

    // AP verifies component hello along with the challenge signature, derives
    // the shared key
    byte ap_shared_key[SHARED_KEY_SIZE];
    word32 ap_shared_key_size = SHARED_KEY_SIZE;

    // This is the component's pubkey as parsed by the AP from the response
    // Saved for verifying challenge response signature
    ed25519_key loaded_comp_pubkey;
    wc_ed25519_init(&loaded_comp_pubkey);

    print_debug("AP verifying component hello: ");

    ret = verify_hello(&comp_hello, ap_shared_key, &ap_shared_key_size, &ap_dh_key,
                       component_id, &loaded_comp_pubkey);
    if (ret != 0)
    {
        print_error("Failed to verify component hello");
        return -1;
    }

    print_debug("AP verifying challenge signature from component");
    ret = verify_data_signature((byte *)ap_hello.sh.hi.dh_pubkey, CURVE25519_PUB_KEY_SIZE,
                                comp_sc.chal_sig, comp_sc.chal_sig_size,
                                &loaded_comp_pubkey);
    if (ret != 0)
    {
        print_error("Signature verification failed");
        return -1;
    }

    print_debug("AP successfully verified component challenge signature");

    // AP now signs component's DH pubkey as its challenge response
    ed25519_key ap_key;
    ret = load_ap_private_key(&ap_key);
    if (ret != 0)
    {
        print_error("Error loading AP key: %d", ret);
        return -1;
    }

    print_debug("AP signing Component dh key as challenge");

    byte ap_chal_sig_out[ED25519_SIG_SIZE];
    word32 ap_chal_sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(comp_hello.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                    ap_chal_sig_out, &ap_chal_sig_sz, &ap_key);
    if (ret != 0)
    {
        print_error("Error signing component DH pubkey with AP key: %d", ret);
        return -1;
    }

    print_debug("Setting challenge signature in response struct");

    signed_chal ap_sc;

    memset(ap_sc.chal_sig, 0, ED25519_SIG_SIZE);
    memcpy(ap_sc.chal_sig, ap_chal_sig_out, ap_chal_sig_sz);
    ap_sc.chal_sig_size = ap_chal_sig_sz;

    // Send this challenge signature to component
    bzero(receive_buffer, sizeof(receive_buffer));

    send_packet(addr, sizeof(ap_sc), (uint8_t *)&ap_sc);

    // Poll for ackowledgement packet to complete handshake
    len = poll_and_receive_packet(addr, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Error while polling for done packet");
    }
    char done[] = "done";
    if (strncmp((char *) receive_buffer, done, sizeof(done)) == 0) {
        // Handshake done 
        int i;
        int session_made = 0;
        for (i = 0; i < COMPONENT_CNT; ++i) {
            component_session* s = &(sessions[i]);
            if (s->component_id == (word32) component_id) {
                s->active = 1;
                memcpy(s->key, ap_shared_key, SHARED_KEY_SIZE);
                s->send_counter = 0;
                s->receive_counter = 0;

                session_made = 1;
            }
        }

        if (session_made != 1) {
            print_error("Could not find session for component id 0x%08x", component_id);
            return -1; 
        }

        print_debug("Leaving do_handshake()");

        // The AP can then poll for a data packet from component through secure_receive
        return 0;
    } else {
        print_error("Component did not send valid done message");
        return -1;
    }
}

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // // Create command message
        // command_message* command = (command_message*) transmit_buffer;
        // command->opcode = COMPONENT_CMD_BOOT;
        
        // // Send out command and receive result
        // int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        // if (len == ERROR_RETURN) {
        //     print_error("Could not boot component\n");
        //     return ERROR_RETURN;
        // }

        word32 component_id = flash_status.component_ids[i];

        // Do handshake with boot command
        int ret = do_handshake(component_id, COMPONENT_CMD_BOOT);
        if (ret != 0) {
            print_error("Error while doing handshake");
            return ERROR_RETURN;
        }

        // Securely receive component boot message
        bzero(receive_buffer, MAX_I2C_MESSAGE_LEN);
        secure_receive(addr, receive_buffer);

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Do handshake
    
    int ret = do_handshake(component_id, COMPONENT_CMD_ATTEST);
    if (ret != 0) {
        print_error("Error while doing handshake");
        return ERROR_RETURN;
    }

    // Buffer for receiving data
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    bzero(receive_buffer, sizeof(receive_buffer));

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Now component will respond with the requested data
    // int len = poll_and_receive_packet(addr, receive_buffer);
    int len = secure_receive(addr, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Error in receiving data packet from component");
        return ERROR_RETURN;
    }

    // Print out attestation data
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    booted = 1;

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else

    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    uint8_t isDelayed;
    // Read into delay_status_pin from flash
    flash_simple_read(DELAY_FLASH_ADDR_PIN, (uint32_t *)&delay_status_pin,
                      sizeof(smaller_flash_entry));
    // If the flash magic is not set, set the local isDelayed to 0
    // Else, set isDelayed to 1
    if (delay_status_pin.flash_magic != FLASH_MAGIC) {
        isDelayed = 0;
        // Make sure flash_magic is set to FLASH_MAGIC for next time (do the
        // delay) until a correct PIN attempt
        delay_status_pin.flash_magic = FLASH_MAGIC;
    }

    else {
        isDelayed = 1;
    }
    // Write the variable to flash BEFORE attempt to prevent circumvention
    flash_simple_erase_page(DELAY_FLASH_ADDR_PIN);
    flash_simple_write(DELAY_FLASH_ADDR_PIN, (uint32_t *)&delay_status_pin,
                       sizeof(smaller_flash_entry));

    if (isDelayed) {
        MXC_TRNG_Init();
        // Random sleep time between 3 and 4.8 seconds for side-channel reasons
        uint32_t sleeptime =
            (((uint32_t)MXC_TRNG_RandomInt()) % 1800000) + 3000000;
        MXC_TRNG_Shutdown();
        MXC_Delay(sleeptime);
    }
    // Always present delay for PIN attempts to max out allowed time
    MXC_Delay(1800000);
    char buf[50];
    recv_input("Enter pin: ", buf, 7);
    if (!secure_cmp(buf, AP_PIN, 6)) {
        // Successful PIN attempt, erase the delay status, no longer under
        // attack
        flash_simple_erase_page(DELAY_FLASH_ADDR_PIN);
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }

    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    uint8_t isDelayed;
    // Read into token_status_pin from flash
    flash_simple_read(DELAY_FLASH_ADDR_TOKEN, (uint32_t *)&delay_status_token,
                      sizeof(smaller_flash_entry));
    // If the flash magic is not set, set the local isDelayed to 0
    // Else, set isDelayed to 1
    if (delay_status_token.flash_magic != FLASH_MAGIC) {
        isDelayed = 0;
        // Make sure flash_magic is set to FLASH_MAGIC for next time (do the
        // delay) until a correct token attempt
        delay_status_token.flash_magic = FLASH_MAGIC;
    }

    else {
        isDelayed = 1;
    }
    // Write the variable to flash BEFORE attempt to prevent circumvention
    flash_simple_erase_page(DELAY_FLASH_ADDR_TOKEN);
    flash_simple_write(DELAY_FLASH_ADDR_TOKEN, (uint32_t *)&delay_status_token,
                       sizeof(smaller_flash_entry));
    if (isDelayed) {
        MXC_TRNG_Init();
        // Random sleep time between 3 and 4.8 seconds for side-channel reasons
        uint32_t sleeptime =
            (((uint32_t)MXC_TRNG_RandomInt()) % 1800000) + 3000000;
        MXC_TRNG_Shutdown();
        MXC_Delay(sleeptime);
    }
    // Always present delay for token attempts to max out allowed time
    MXC_Delay(4800000);
    char buf[50];
    recv_input("Enter token: ", buf, 9);
    if (!secure_cmp(buf, AP_TOKEN, 8)) {
        // Successful token attempt, erase the delay status, no longer under attack
        flash_simple_erase_page(DELAY_FLASH_ADDR_TOKEN);
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
       print_error("Components could not be validated\n");
       return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
       print_error("Failed to boot all components\n");
       return;
    }

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, 11);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, 11);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            // Reset session for old component id and assign new id
            // for (int i = 0; i < COMPONENT_CNT; ++i) {
            //     if (sessions[i].component_id == component_id_out) {
            //         component_session* session = &(sessions[i]);

            //         session->component_id = (word32) component_id_in;
            //         session->active = 0;
            //         bzero(session->key, SHARED_KEY_SIZE);
            //         session->send_counter = 0;
            //         session->receive_counter = 0;
            //     }
            // }

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");

            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf, 11);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf, 8);

        // Execute requested command
        if (!strncmp(buf, "list", 4)) {
            scan_components();
        } else if (!strncmp(buf, "boot", 4)) {
            attempt_boot();
        } else if (!strncmp(buf, "replace", 7)) {
            attempt_replace();
        } else if (!strncmp(buf, "attest", 6)) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
