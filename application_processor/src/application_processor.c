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
#include "crypto_aes.h"
#include "crypto_test.h"
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
    word32 sendCounter;
    word32 receiveCounter;
} component_session;

// Struct for storing auth tags
typedef struct {
    byte iv[GCM_IV_SIZE];
    word32 counter; 
} message_auth;

component_session sessions[COMPONENT_CNT];

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/********************************* REFERENCE FLAG **********************************/
// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// NOTE: you're not allowed to do this in your code
// Remove this in your design
typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x12614f7,0x1ffe4b6,0x11a38bb,0x1ffe4b6,0x12614f7,0x1ffe4b6,0x12220e3,0x3098ac,0x1ffe4b6,0x2ca498,0x11a38bb,0xe6d3b7,0x1ffe4b6,0x127bc,0x3098ac,0x11a38bb,0x1d073c6,0x51bd0,0x127bc,0x2e590b1,0x1cc7fb2,0x1d073c6,0xeac7cb,0x51bd0,0x2ba13d5,0x2b22bad,0x2179d2e,0};const aErjfkdfru djFIehjkklIH[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x38ec6f2,0x138e798,0x23bcfda,0x138e798,0x38ec6f2,0x138e798,0x31dc9ea,0x2cdbb14,0x138e798,0x25cbe0c,0x23bcfda,0x199a72,0x138e798,0x11c82b4,0x2cdbb14,0x23bcfda,0x3225338,0x18d7fbc,0x11c82b4,0x35ff56,0x2b15630,0x3225338,0x8a977a,0x18d7fbc,0x29067fe,0x1ae6dee,0x4431c8,0};typedef int skerufjp;skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}

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
    return send_packet(address, len, buffer);
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
    return poll_and_receive_packet(address, buffer);
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
    }
    
    // Initialize board link interface
    board_link_init();

    // Initialize sessions array
    uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
    for (int i = 0; i < COMPONENT_CNT; ++i) {
        component_session* session = &(sessions[i]);
        session->component_id = (word32) component_ids[i];
        session->active = 0;
        bzero(session->key, SHARED_KEY_SIZE);
        session->sendCounter = 0;
        session->receiveCounter = 0;
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
                       COMPONENT_ID, &loaded_comp_pubkey);
    if (ret != 0)
    {
        print_debug("Failed to verify component hello");
        return -1;
    }

    print_debug("AP verifying challenge signature from component");
    ret = verify_data_signature((byte *)ap_hello.sh.hi.dh_pubkey, CURVE25519_PUB_KEY_SIZE,
                                comp_sc.chal_sig, comp_sc.chal_sig_size,
                                &loaded_comp_pubkey);
    if (ret != 0)
    {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("AP successfully verified component challenge signature");

    // AP now signs component's DH pubkey as its challenge response
    ed25519_key ap_key;
    ret = load_ap_private_key(&ap_key);
    if (ret != 0)
    {
        print_debug("Error loading AP key: %d", ret);
        return -1;
    }

    print_debug("AP signing Component dh key as challenge");

    byte ap_chal_sig_out[ED25519_SIG_SIZE];
    word32 ap_chal_sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(comp_hello.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                    ap_chal_sig_out, &ap_chal_sig_sz, &ap_key);
    if (ret != 0)
    {
        print_debug("Error signing component DH pubkey with AP key: %d", ret);
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

    // The handshake finishes here, the AP can then poll for a data packet from component
    return 0;
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
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

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
    int len = poll_and_receive_packet(addr, receive_buffer);
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
    char buf[50];
    recv_input("Enter pin: ", buf);
    if (!strcmp(buf, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    if (!strcmp(buf, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    #ifdef CRYPTO_EXAMPLE

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";

    // Print crypto example
    print_debug("Original Data: %s\r\n", (uint8_t*)data);

    byte ciphertext[BLOCK_SIZE];

    byte key[SHARED_KEY_SIZE];
    // Zero out the key
    bzero(key, SHARED_KEY_SIZE);

    // IV for GCM mode
    byte iv[GCM_IV_SIZE];
    wc_GenerateSeed(NULL, iv, GCM_IV_SIZE); // Initialize IV value using MXC TRNG 

    // Tag for GCM mode - has to be GCM_TAG_SIZE
    byte tag[GCM_TAG_SIZE];
    bzero(tag, GCM_TAG_SIZE);

    message_auth auth;
    memcpy(auth.iv, iv, GCM_IV_SIZE);
    auth.counter = 0;

    // Encrypt example data and print out
    int ret = encrypt_aesgcm(data, BLOCK_SIZE, ciphertext, key, SHARED_KEY_SIZE, iv, GCM_IV_SIZE, &auth, sizeof(auth), &tag); 
    if (ret != 0) {
        print_debug("Failed to encrypt message: error code %d", ret);
    }

    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Decrypt the encrypted message and print out
    byte decrypted[BLOCK_SIZE];
    ret = decrypt_aesgcm(decrypted, BLOCK_SIZE, ciphertext, key, SHARED_KEY_SIZE, auth.iv, GCM_IV_SIZE, &auth, sizeof(auth), &tag);
    if (ret != 0) {
        print_debug("Failed to decrypt message: error code %d", ret);
    }
    print_debug("Decrypted message: %s\r\n", decrypted);

    // simulate_handshake();

    #endif


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

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

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
    recv_input("Component ID: ", buf);
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
        recv_input("Enter Command: ", buf);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
