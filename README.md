# BThack - PoC of the Method Confusion Attack on Bluetooth Pairing

### Original paper: [Method Confusion Attack on Bluetooth Pairing](https://www.computer.org/csdl/proceedings-article/sp/2021/893400a213/1mbmHzm2Q6c)

## Affected devices + Threat status
CVE: [CERT report](https://kb.cert.org/vuls/id/534195)
Bluetooth SIG: [SIG security alert](https://www.bluetooth.com/learn-about-bluetooth/bluetooth-technology/bluetooth-security/reporting-security/)
Apple: [iOS / IPadOS](https://support.apple.com/en-us/HT211168)
Google: ...

*Every pairing between any Bluetooth devices using Numeric Comparison or Passkey Entry is vulnerable to the Method Confusion attack.*

#### Fix
Currently there is **no fix available** that would not massively affect backwards compatibility to older Bluetooth devices.

Device vendors can only try to educate their users about the threat and visualize the utilized pairing method prominently  *(providing aware and versed users the possibility to detect an ongoing attack)*.

This is of course just a mild mitigation and entirely **defeats the idea of a simple and secure TOFU establishment**.


Bluetooths security model has to be considered **broken** until a solution is found.
We are following the decisions of the Bluetooth SIG closely.

## PoC - BThack
This PoC is intended to make reproduction of the issue as easy as possible.
If you encounter any difficulties or find a description to imprecise please reach out so we can improve.

### Structure of the BThack framework

* **[UI interface](https://github.com/maxdos64/BThack/blob/master/attack.py)** - Python script with some pleasant(?) graphics to control the whole framework
* **[Controller interaction](https://github.com/lupinglui/btstack/tree/bthack_mods)** - Customized version of the [BTstack](https://github.com/bluekitchen/btstack) library
* **[Numeric on Passkey implementation](https://github.com/maxdos64/BThack/tree/master/NoP)** - C program that utelizes the custom BTstack library
* **[Passkey on Numeric implementation](https://github.com/maxdos64/BThack/tree/master/PoN)** - C program that utelizes the custom BTstack library
* **[Jamming implementation](https://github.com/maxdos64/btlejack/tree/disable_fix)** - Customized version of btlejack and btlejack-firmware 

### Usage
0. ==**Please check this repo out using 'git clone --recurse-submodules'**==
1. Run the Makefiles in the subdirectories of the desired attack variants (pon, nop, full_mitm)
2. Connect 2 USB Bluetooth controller that are compatible with BTstack ([list](https://github.com/bluekitchen/btstack#evaluation-platforms)) - they should appear under `lsusb`

You have two different complexities of the attack available:

##### A. Attack without suppressing the original victims advertisements:
1. Enter the folder of the desired attack variant
2. Call the respective binary (nop, pon, full_mitm); provide the target address and the lsusb-identifiers of your dongles

##### B. Attack with suppressing the original victims advertisements:
1. Add at least 3 micro:bit devices if you want to suppress victim advertisments
2. Start the [attack.py](https://github.com/maxdos64/BThack/blob/master/attack.py) script
3. Select your devices and the attack mode ('auto' selects the optimal method dynamically) 


##### Suppressing victim advertisements
In order to lead a realistic victim-Initiator into attempting the pairing with our MitM-Responder the framework offers the option to selectively jam the advertisement messages of the victim-Responder. In this case at least 3 [BBC:microbits](https://microbit.org/) are required as they contain the 
[nrf5x](https://www.nordicsemi.com/Products/Low-power-short-range-wireless/nRF51822) chip that is utelized for jamming. For this option you are also required to flash the microbits with our customized version of the btlejack-firmware (See Readme in the respective subfolder)
