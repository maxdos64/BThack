
// watch.h generated from watch.gatt for BTstack
// it needs to be regenerated when the .gatt file is updated. 

// To generate watch.h:
// ../btstack/tool/compile_gatt.py watch.gatt watch.h

// att db format version 1

// binary attribute representation:
// - size in bytes (16), flags(16), handle (16), uuid (16/128), value(...)

#include <stdint.h>

const uint8_t profile_data[] =
{
    // ATT DB Version
    1,

    // 0x0001 PRIMARY_SERVICE-GAP_SERVICE
    0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 
    // 0x0002 CHARACTERISTIC-GAP_DEVICE_NAME-READ
    0x0d, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x00, 0x2a, 
    // 0x0003 VALUE-GAP_DEVICE_NAME-READ-'Galaxy Watch (052E) LE'
    // READ_ANYBODY
    0x1e, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x2a, 0x47, 0x61, 0x6c, 0x61, 0x78, 0x79, 0x20, 0x57, 0x61, 0x74, 0x63, 0x68, 0x20, 0x28, 0x30, 0x35, 0x32, 0x45, 0x29, 0x20, 0x4c, 0x45, 
    //[NEW] Primary Service (Handle 0x77ce)
    //        /org/bluez/hci0/dev_C4_69_52_37_AB_5C/service0006
    //        Generic Attribute Profile

    // 0x0004 PRIMARY_SERVICE-00001801-0000-1000-8000-00805f9b34fb
    0x18, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x28, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x01, 0x18, 0x00, 0x00, 
    //[NEW] Characteristic (Handle 0x77ce)
    //        /org/bluez/hci0/dev_C4_69_52_37_AB_5C/service0006/char0007
    //        Service Changed
    // 0x0005 CHARACTERISTIC-00002a05-0000-1000-8000-00805f9b34fb-DYNAMIC
    0x1b, 0x00, 0x02, 0x00, 0x05, 0x00, 0x03, 0x28, 0x00, 0x06, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x05, 0x2a, 0x00, 0x00, 
    // 0x0006 VALUE-00002a05-0000-1000-8000-00805f9b34fb-DYNAMIC-'Secure :)'
    // 
    0x1f, 0x00, 0x00, 0x03, 0x06, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x05, 0x2a, 0x00, 0x00, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x3a, 0x29, 
    //[NEW] Descriptor (Handle 0x000c)
    //        /org/bluez/hci0/dev_C4_69_52_37_AB_5C/service0006/char0007/desc0009
    //        00002902-0000-1000-8000-00805f9b34fb
    //        Client Characteristic Configuration
    // 0x0007 CHARACTERISTIC-00002902-0000-1000-8000-00805f9b34fb-DYNAMIC
    0x1b, 0x00, 0x02, 0x00, 0x07, 0x00, 0x03, 0x28, 0x00, 0x08, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x02, 0x29, 0x00, 0x00, 
    // 0x0008 VALUE-00002902-0000-1000-8000-00805f9b34fb-DYNAMIC-'Secure :)'
    // 
    0x1f, 0x00, 0x00, 0x03, 0x08, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x02, 0x29, 0x00, 0x00, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x3a, 0x29, 
    //[CHG] Device C4:69:52:37:AB:5C UUIDs: 00001800-0000-1000-8000-00805f9b34fb

    // 0x0009 PRIMARY_SERVICE-00001800-0000-1000-8000-00805f9b34fb
    0x18, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x28, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 

    // END
    0x00, 0x00, 
}; // total size 127 bytes 


//
// list service handle ranges
//
#define ATT_SERVICE_GAP_SERVICE_START_HANDLE 0x0001
#define ATT_SERVICE_GAP_SERVICE_END_HANDLE 0x0003
#define ATT_SERVICE_00001801_0000_1000_8000_00805f9b34fb_START_HANDLE 0x0004
#define ATT_SERVICE_00001801_0000_1000_8000_00805f9b34fb_END_HANDLE 0x0008
#define ATT_SERVICE_00001800_0000_1000_8000_00805f9b34fb_START_HANDLE 0x0009
#define ATT_SERVICE_00001800_0000_1000_8000_00805f9b34fb_END_HANDLE 0x0009

//
// list mapping between characteristics and handles
//
#define ATT_CHARACTERISTIC_GAP_DEVICE_NAME_01_VALUE_HANDLE 0x0003
#define ATT_CHARACTERISTIC_00002a05_0000_1000_8000_00805f9b34fb_01_VALUE_HANDLE 0x0006
#define ATT_CHARACTERISTIC_00002902_0000_1000_8000_00805f9b34fb_01_VALUE_HANDLE 0x0008
