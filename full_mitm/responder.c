#define __BTSTACK_FILE__ "main.c"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "btstack_debug.h"
#include "btstack_event.h"
#include "btstack_link_key_db_fs.h"
#include "btstack_memory.h"
#include "btstack_run_loop.h"
#include "btstack_run_loop_posix.h"
#include "hal_led.h"
#include "hci.h"
#include "hci_dump.h"
#include "btstack_stdin.h"
#include "btstack_audio.h"
#include "btstack_tlv_posix.h"
#include "bluetooth_data_types.h"
#include "bluetooth_company_id.h"
#include "../chipset/zephyr/btstack_chipset_zephyr.h"
#include "ble/le_device_db.h"
#include "ble/att_server.h"
#include <unistd.h>

#include <libusb.h>
#include <sys/wait.h>

#include "profiles.h"
#include "btstack_config.h"

#define TLV_DB_PATH_PREFIX "/tmp/btstack_"
#define TLV_DB_PATH_POSTFIX ".tlv"
#define USB_MAX_PATH_LEN 7
#define FIXED_PASSKEY 123456
#define REMOTE_SERVICE 0x1111
const char secret[] = "flag{RESPONDER_SECRET}";

/* Helper structs */

/* Globals */
static char tlv_db_path[100];
static const btstack_tlv_t * tlv_impl;
static btstack_tlv_posix_t   tlv_context;
static bd_addr_t             local_addr;
static uint8_t data_channel_buffer[TEST_PACKET_SIZE];
static uint16_t initial_credits = L2CAP_LE_AUTOMATIC_CREDITS;
uint16_t connection_id;

static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

static const uint8_t read_static_address_command_complete_prefix[] = { 0x0e, 0x1b, 0x01, 0x09, 0xfc };
static bd_addr_t static_address;
static int using_static_address;

/* Predefines */
int btstack_main(int argc, const char * argv[]);

const uint8_t adv_data[] = {
	// Flags general discoverable, BR/EDR not supported
	0x02, BLUETOOTH_DATA_TYPE_FLAGS, 0x06,
	// Name
	0x0b, BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME, 'C', 'A', 'R', 'D', 'R', 'E', 'A', 'D', 'E', 'R',
	// Incomplete List of 16-bit Service Class UUIDs -- 1111 - only valid for testing!
	0x03, BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, 0x11, 0x11,
};
const uint8_t adv_data_len = sizeof(adv_data);

static void local_version_information_handler(uint8_t * packet)
{
	printf("Local version information:\n");
	uint16_t hci_version    = packet[6];
	uint16_t hci_revision   = little_endian_read_16(packet, 7);
	uint16_t lmp_version    = packet[9];
	uint16_t manufacturer   = little_endian_read_16(packet, 10);
	uint16_t lmp_subversion = little_endian_read_16(packet, 12);
	printf("- HCI Version    0x%04x\n", hci_version);
	printf("- HCI Revision   0x%04x\n", hci_revision);
	printf("- LMP Version    0x%04x\n", lmp_version);
	printf("- LMP Subversion 0x%04x\n", lmp_subversion);
	printf("- Manufacturer 0x%04x\n", manufacturer);
	switch (manufacturer)
	{
		case BLUETOOTH_COMPANY_ID_THE_LINUX_FOUNDATION:
			printf("Linux Foundation - assume Zephyr hci_usb example running on nRF52xx\n");
			hci_set_chipset(btstack_chipset_zephyr_instance());
			break;
		default:
			break;
	}
}

static void l2cap_server_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
        UNUSED(channel);
	UNUSED(size);

        bd_addr_t event_address;
        uint16_t psm;
        uint16_t temp_connection_id;
        hci_con_handle_t handle;

        switch (packet_type)
        {
                case HCI_EVENT_PACKET:
                        switch (hci_event_packet_get_type(packet))
                        {
                                case L2CAP_EVENT_LE_INCOMING_CONNECTION:
                                        printf("L2CAP: incomming connection\n");
                                        psm = l2cap_event_le_incoming_connection_get_psm(packet);
                                        temp_connection_id = l2cap_event_le_incoming_connection_get_local_cid(packet);
                                        if (psm != TSPX_le_psm)
                                                break;
                                        printf("L2CAP: Accepting incoming LE connection request for 0x%02x, PSM %02x\n", temp_connection_id, psm);
                                        l2cap_le_accept_connection(temp_connection_id, data_channel_buffer, sizeof(data_channel_buffer), initial_credits);
                                        break;

                                case L2CAP_EVENT_LE_CHANNEL_OPENED:
                                        l2cap_event_le_channel_opened_get_address(packet, event_address);
                                        psm = l2cap_event_le_channel_opened_get_psm(packet);
                                        temp_connection_id = l2cap_event_le_channel_opened_get_local_cid(packet);
                                        handle = l2cap_event_le_channel_opened_get_handle(packet);
                                        if (packet[2] == 0)
                                        {
                                                printf("L2CAP: LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
                                                connection_id = temp_connection_id;
                                                l2cap_le_request_can_send_now_event(connection_id);
                                        }
                                        else
                                        {
                                                printf("L2CAP: LE Data Channel connection to device %s failed. status code %u\n", bd_addr_to_str(event_address), packet[2]);
                                        }
                                        break;

                                case L2CAP_EVENT_LE_CHANNEL_CLOSED:
                                        printf("RESP: L2CAP: LE Data Channel closed\n");
                                        connection_id = 0;
                                        break;

                                /* Start sending the secret */
                                case L2CAP_EVENT_LE_CAN_SEND_NOW:
                                        // printf("RESP: L2CAP Can send now\n");
                                        l2cap_le_send_data(connection_id, (uint8_t *)secret, strlen(secret) + 1);

                                        /* Request another packet */
                                        sleep(1);
                                        l2cap_le_request_can_send_now_event(connection_id);
                                        break;
                        }
                        break;

                case L2CAP_DATA_PACKET:
                        printf("RESP: Received secret: %s\n", packet);
                        break;
        }
}

static void responder_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	bd_addr_t addr;
	hci_con_handle_t hci_con_handle;
	char buf[10];
	uint32_t passkey;

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet)) {
				case HCI_EVENT_LE_META:
					switch (hci_event_le_meta_get_subevent_code(packet)) {
						case HCI_SUBEVENT_LE_CONNECTION_COMPLETE:
							// setup new
							printf("RESP: Connection complete\n");
                    hci_con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
						  sm_send_security_request(hci_con_handle);
						  break;
						default:
						  break;
					}
					break;
				case SM_EVENT_JUST_WORKS_REQUEST:
					printf("RESP: Just Works requested\n");
					sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
					break;
				case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
					printf("\n\nRESP: Confirming numeric comparison: \e[31m%d\e[0m\n\n\n", sm_event_numeric_comparison_request_get_passkey(packet));
					sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
					break;
				case SM_EVENT_PASSKEY_INPUT_NUMBER:
					printf("INIT: Passkey Input requested\n Please Enter>\n");
					fgets(buf, 10, stdin);
					passkey = (uint32_t) atoi(buf);
					printf("INIT: Sending passkey %d\n", passkey);
					sm_passkey_input(sm_event_passkey_input_number_get_handle(packet), passkey);
					break;
				case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
					printf("RESP: Display Passkey: %d\n", sm_event_passkey_display_number_get_passkey(packet));
					break;
				case SM_EVENT_IDENTITY_CREATED:
					sm_event_identity_created_get_identity_address(packet, addr);
					printf("RESP: Identity created\n");
					// printf("Identity created: type %u address %s\n", sm_event_identity_created_get_identity_addr_type(packet), bd_addr_to_str(addr));
					break;
				case SM_EVENT_IDENTITY_RESOLVING_SUCCEEDED:
					sm_event_identity_resolving_succeeded_get_identity_address(packet, addr);
					printf("RESP: Identity resolved\n");
					// printf("Identity resolved: type %u address %s\n", sm_event_identity_resolving_succeeded_get_identity_addr_type(packet), bd_addr_to_str(addr));
					break;
				case SM_EVENT_IDENTITY_RESOLVING_FAILED:
					sm_event_identity_created_get_address(packet, addr);
					printf("RESP: Identity resolving failed\n");
					break;
				case SM_EVENT_PAIRING_COMPLETE:
					switch (sm_event_pairing_complete_get_status(packet))
					{
						case ERROR_CODE_SUCCESS:
							printf("RESP: Pairing complete, success\n");
							break;
						case ERROR_CODE_CONNECTION_TIMEOUT:
							printf("RESP: Pairing failed, timeout\n");
							break;
						case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
							printf("RESP: Pairing faileed, disconnected\n");
							break;
						case ERROR_CODE_AUTHENTICATION_FAILURE:
							printf("RESP: Pairing failed, reason = %u\n", sm_event_pairing_complete_get_reason(packet));
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
			break;
	}
}

static void general_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	if (packet_type != HCI_EVENT_PACKET) return;
	switch (hci_event_packet_get_type(packet))
	{
		case BTSTACK_EVENT_STATE:
			if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING) return;
			gap_local_bd_addr(local_addr);
			if (using_static_address)
				memcpy(local_addr, static_address, 6);

			printf("INIT(GEN): BThack up and running on %s.\n", bd_addr_to_str(local_addr));
			strcpy(tlv_db_path, TLV_DB_PATH_PREFIX);
			strcat(tlv_db_path, bd_addr_to_str(local_addr));
			strcat(tlv_db_path, TLV_DB_PATH_POSTFIX);
			tlv_impl = btstack_tlv_posix_init_instance(&tlv_context, tlv_db_path);
			btstack_tlv_set_instance(tlv_impl, &tlv_context);
			break;

		case HCI_EVENT_COMMAND_COMPLETE:
			if (HCI_EVENT_IS_COMMAND_COMPLETE(packet, hci_read_local_version_information))
				local_version_information_handler(packet);

			if (memcmp(packet, read_static_address_command_complete_prefix, sizeof(read_static_address_command_complete_prefix)) == 0)
			{
				reverse_48(&packet[7], static_address);
				gap_random_address_set(static_address);
				using_static_address = 1;
			}
			break;

		default:
			break;
	}
}

static void sigint_handler(int param)
{
	UNUSED(param);

	printf("RESP: CTRL-C - SIGINT received, shutting down..\n");
	log_info("RESP: sigint_handler: shutting down");

	btstack_stdin_reset();

	hci_power_control(HCI_POWER_OFF);
	hci_close();

	log_info("RESP: Good bye, see you.\n");
	exit(0);
}

static void register_mitm_options(void)
{
	struct SmMitmOptions* mitm_options = calloc(1, sizeof(struct SmMitmOptions));
	mitm_options->turnoff_dhkey_validation = 1;
	sm_register_mitm_options(mitm_options);
}

int main(int argc, const char * argv[])
{
	char pklg_path[100];
	uint8_t responder_usb_device_id;

	/* Parse arguments */
	if(argc < 3)
	{
		printf("Too few arguments provided\n");
		printf("Usage:./%s [responder_device_id] [IO_CAPs]\n", argv[0]);
		exit(0);
	}
	responder_usb_device_id = strtol(argv[1], 0, 10);

	signal(SIGINT, sigint_handler);

	btstack_memory_init();
	btstack_run_loop_init(btstack_run_loop_posix_get_instance());

	hci_transport_usb_set_address(responder_usb_device_id);

	/* Logger */
	strcpy(pklg_path, "/tmp/hci_dump_test_responder");
	strcat(pklg_path, ".pklg");
	printf("Packet Log: %s\n", pklg_path);
	hci_dump_open(pklg_path, HCI_DUMP_PACKETLOGGER);

	hci_init(hci_transport_usb_instance(), NULL);
	l2cap_init();
	le_device_db_init();
	register_mitm_options();
	sm_init();

	hci_event_callback_registration.callback = &general_hci_packet_handler;
	hci_add_event_handler(&hci_event_callback_registration);

	l2cap_register_packet_handler(&l2cap_server_packet_handler);
	l2cap_le_register_service(&l2cap_server_packet_handler, TSPX_le_psm, LEVEL_2);

	if (!strcmp(argv[2], "NO_INPUT_NO_OUTPUT"))
	{
		printf("NOTE: THIS IS NOT VALID FOR METHOD CONFUSION ATTACK!\n");
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);
		sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
	}
	else if (!strcmp(argv[2], "DISPLAY_ONLY"))
	{
		printf("NOTE: THIS IS NOT VALID FOR METHOD CONFUSION ATTACK!\n");
		sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
	}
	else if (!strcmp(argv[2], "KEYBOARD_ONLY"))
	{
		sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_ONLY);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
	}
	else if (!strcmp(argv[2], "KEYBOARD_DISPLAY"))
	{
		sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_DISPLAY);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
	}
	else if (!strcmp(argv[2], "DISPLAY_YES_NO"))
	{
		sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
	}
	else
	{
		printf("INVALID IOCAPs: [%s]\n", argv[2]);
		exit(1);
	}

	/* setup ATT server */
	att_server_init(responder_profile_data, NULL, NULL);

	/* Setup advertisements */
	uint16_t adv_int_min = 0x0030;
	uint16_t adv_int_max = 0x0030;
	uint8_t adv_type = 0;
	bd_addr_t null_addr;
	memset(null_addr, 0, 6);
	gap_advertisements_set_params(adv_int_min, adv_int_max, adv_type, 0, null_addr, 0x07, 0x00);
	gap_advertisements_set_data(adv_data_len, (uint8_t*) adv_data);
	gap_advertisements_enable(1);

	sm_event_callback_registration.callback = &responder_sm_packet_handler;
	sm_add_event_handler(&sm_event_callback_registration);

	// Register for ATT
	att_server_register_packet_handler(responder_sm_packet_handler);

	hci_power_control(HCI_POWER_ON);
	printf("RESP: Initialized\n");

	btstack_run_loop_execute();

	return 0;
}
