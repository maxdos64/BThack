#define __BTSTACK_FILE__ "main.c"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>

#include "btstack_run_loop.h"
#include "btstack_run_loop_posix.h"
#include <libusb.h>

#include "btstack.h"
#include "btstack_config.h"

static btstack_packet_callback_registration_t hci_event_callback_registration;

static const char * ad_types[] = {
	"",
	"Flags",
	"Incomplete List of 16-bit Service Class UUIDs",
	"Complete List of 16-bit Service Class UUIDs",
	"Incomplete List of 32-bit Service Class UUIDs",
	"Complete List of 32-bit Service Class UUIDs",
	"Incomplete List of 128-bit Service Class UUIDs",
	"Complete List of 128-bit Service Class UUIDs",
	"Shortened Local Name",
	"Complete Local Name",
	"Tx Power Level",
	"",
	"",
	"Class of Device",
	"Simple Pairing Hash C",
	"Simple Pairing Randomizer R",
	"Device ID",
	"Security Manager TK Value",
	"Slave Connection Interval Range",
	"",
	"List of 16-bit Service Solicitation UUIDs",
	"List of 128-bit Service Solicitation UUIDs",
	"Service Data",
	"Public Target Address",
	"Random Target Address",
	"Appearance",
	"Advertising Interval"
};

static const char * flags[] = {
	"LE Limited Discoverable Mode",
	"LE General Discoverable Mode",
	"BR/EDR Not Supported",
	"Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
	"Simultaneous LE and BR/EDR to Same Device Capable (Host)",
	"Reserved",
	"Reserved",
	"Reserved"
};

static void dump_advertisement_data(const uint8_t * adv_data, uint8_t adv_size){
	ad_context_t context;
	bd_addr_t address;
	uint8_t uuid_128[16];
	for (ad_iterator_init(&context, adv_size, (uint8_t *)adv_data) ; ad_iterator_has_more(&context) ; ad_iterator_next(&context)){
		uint8_t data_type    = ad_iterator_get_data_type(&context);
		uint8_t size         = ad_iterator_get_data_len(&context);
		const uint8_t * data = ad_iterator_get_data(&context);

		// if (data_type > 0 && data_type < 0x1B){
		// 	printf("    %s: ", ad_types[data_type]);
		// }
		int i;
		// Assigned Numbers GAP

		switch (data_type){
			// case BLUETOOTH_DATA_TYPE_FLAGS:
			// 	// show only first octet, ignore rest
			// 	for (i=0; i<8;i++){
			// 		if (data[0] & (1<<i)){
			// 			printf("%s; ", flags[i]);
			// 		}

			// 	}
			// 	break;
			// case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:
			// 	for (i=0; i<size;i+=2){
			// 		printf("%02X ", little_endian_read_16(data, i));
			// 	}
			// 	break;
			// case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:
			// 	for (i=0; i<size;i+=4){
			// 		printf("%04", little_endian_read_32(data, i));
			// 	}
			// 	break;
			// case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
			// case BLUETOOTH_DATA_TYPE_LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:
			// 	reverse_128(data, uuid_128);
			// 	printf("%s", uuid128_to_str(uuid_128));
			// 	break;
			case BLUETOOTH_DATA_TYPE_SHORTENED_LOCAL_NAME:
			case BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME:
				for (i=0; i<size;i++){
					printf("%c", (char)(data[i]));
				}
				break;
			// case BLUETOOTH_DATA_TYPE_TX_POWER_LEVEL:
			// 	printf("%d dBm", *(int8_t*)data);
			// 	break;
			// case BLUETOOTH_DATA_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE:
			// 	printf("Connection Interval Min = %u ms, Max = %u ms", little_endian_read_16(data, 0) * 5/4, little_endian_read_16(data, 2) * 5/4);
			// 	break;
			// case BLUETOOTH_DATA_TYPE_SERVICE_DATA:
			// 	printf_hexdump(data, size);
			// 	break;
			// case BLUETOOTH_DATA_TYPE_PUBLIC_TARGET_ADDRESS:
			// case BLUETOOTH_DATA_TYPE_RANDOM_TARGET_ADDRESS:
			// 	reverse_bd_addr(data, address);
			// 	printf("%s", bd_addr_to_str(address));
			// 	break;
			// case BLUETOOTH_DATA_TYPE_APPEARANCE: 
			// 	// https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicViewer.aspx?u=org.bluetooth.characteristic.gap.appearance.xml
			// 	printf("%02X", little_endian_read_16(data, 0) );
			// 	break;
			// case BLUETOOTH_DATA_TYPE_ADVERTISING_INTERVAL:
			// 	printf("%u ms", little_endian_read_16(data, 0) * 5/8 );
			// 	break;
			// case BLUETOOTH_DATA_TYPE_3D_INFORMATION_DATA:
			// 	printf_hexdump(data, size);
			// 	break;
			// case BLUETOOTH_DATA_TYPE_MANUFACTURER_SPECIFIC_DATA: // Manufacturer Specific Data 
			// 	break;
			// case BLUETOOTH_DATA_TYPE_CLASS_OF_DEVICE:
			// case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_HASH_C:
			// case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_RANDOMIZER_R:
			// case BLUETOOTH_DATA_TYPE_DEVICE_ID: 
			// case BLUETOOTH_DATA_TYPE_SECURITY_MANAGER_OUT_OF_BAND_FLAGS:
			// default:
			// 	printf("Advertising Data Type 0x%2x not handled yet", data_type); 
			// 	break;
		}
		// printf("\n");
	}
	printf("\n");
}

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
	UNUSED(channel);
	UNUSED(size);

	if (packet_type != HCI_EVENT_PACKET) return;

	switch (hci_event_packet_get_type(packet)) {
		case GAP_EVENT_ADVERTISING_REPORT:
			{
				bd_addr_t address;
				gap_event_advertising_report_get_address(packet, address);
				uint8_t event_type = gap_event_advertising_report_get_advertising_event_type(packet);
				uint8_t address_type = gap_event_advertising_report_get_address_type(packet);
				int8_t rssi = gap_event_advertising_report_get_rssi(packet);
				uint8_t length = gap_event_advertising_report_get_data_length(packet);
				const uint8_t * data = gap_event_advertising_report_get_data(packet);

				printf("%s, %d, ", bd_addr_to_str(address), rssi);
				dump_advertisement_data(data, length);
				break;
			}
		default:
			break;
	}
}

static void sigint_handler(int param)
{
	UNUSED(param);

	printf("INIT: CTRL-C - SIGINT received, shutting down..\n");
	log_info("INIT: sigint_handler: shutting down");

	btstack_stdin_reset();

	hci_power_control(HCI_POWER_OFF);
	hci_close();

	log_info("INIT: Good bye, see you.\n");
	exit(0);
}

int main(int argc, const char * argv[])
{
	char pklg_path[100];
	uint8_t initiator_usb_device_id;

	/* Turn on line buffering for stdout (interaction with python scripts) */
	setvbuf(stdout, 0, _IOLBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	/* Parse arguments */
	if(argc < 2)
	{
		printf("Too few arguments provided\n");
		printf("Usage:./%s device_id\n", argv[0]);
		exit(0);
	}
	initiator_usb_device_id = strtol(argv[1], 0, 10);

	signal(SIGINT, sigint_handler);

	btstack_memory_init();
	btstack_run_loop_init(btstack_run_loop_posix_get_instance());

	hci_transport_usb_set_address(initiator_usb_device_id);

	/* Logger */
	strcpy(pklg_path, "/tmp/hci_dump_test_initiator");
	strcat(pklg_path, ".pklg");
	printf("Packet Log: %s\n", pklg_path);
	hci_dump_open(pklg_path, HCI_DUMP_PACKETLOGGER);

	hci_init(hci_transport_usb_instance(), NULL);

	gap_set_scan_parameters(1, 48, 48);
	gap_start_scan();

	hci_event_callback_registration.callback = &packet_handler;
	hci_add_event_handler(&hci_event_callback_registration);

	/* Turn on! */
	hci_power_control(HCI_POWER_ON);

	btstack_run_loop_execute();

	return 0;
}
