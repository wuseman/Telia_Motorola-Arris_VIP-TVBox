# TeliaSonera AB - Motorola Arris VIP IPTV-STB

![arris_banner](https://github.com/user-attachments/assets/da1b7fa2-7924-4fcd-8c36-ea7c572410dd)

Unlocking the Motorola Arris IPTV-STB: A Technical Deep Dive provides an exhaustive analysis of the Motorola Arris Set-Top Box distributed by TeliaSonera AB. This guide covers everything from hardware disassembly, bootloader encryption issues, to advanced firmware decryption techniques, aimed at enthusiasts seeking to fully understand and leverage their device's capabilities. Note the emphasis on ethical research and GPL compliance discussions, inviting further community insights into secure and open device usage.

## Boot Process

The CPU boots from the M28W320, which contains a first-stage bootloader in the lower 64 KB. This bootloader decrypts the second-stage bootloader starting at offset `0x10000`. This is essentially a Linux kernel with a small ramdisk attached.

## Disclaimer

!!! Note "This analysis stems from personal research and disassembly of the Motorola Arris STB Box from TeliaSonera AB, Sweden. The documentation in this readme is originally authored by myself, as per usual practice. Unfortunately, the decryption tool referenced from that era is no longer accurate. It's essential to note that I refrain from distributing any `decryption` tool for this purpose publicly. For those interested in further details, please don't hesitate to reach out. I've successfully developed a current decryption tool applicable to all Motorola and Arris TV Boxes, covering devices up to the year 2024."

!!! Danger "Danger: Arris/Motorola's/Telia's decision to encrypt the second-stage bootloader raises concerns, particularly given the apparent ease of extracting the decryption key. Such a decision may raise questions about the transparency of utilizing Linux within the box, potentially prompting inquiries regarding GPL compliance. As I'm not familiar enough with exact details, I'll let this be a reminder that everyone can join in and contribute, if you have insight into whether or not this is OK or not, please let me know, I'll be happy to help. This is the reason for all this work I have done in this `README` for everyone out there"

!!! Example "General Info"

    ```
    User-Agent (OLD).....................: KreaTVWebKit/531 (Motorola STB; Linux)
    User-Agent...........................: KreaTVWebKit/600 (Motorola STB; Linux; 5305)
    Default login URL....................: http://iptvlogin.telia.se/credentials
    Login URL for Device Codes...........: http://iptvlogin.telia.se/iptvgui/guiV8_13_03_433d01a514_swe
    Login Referer URL....................: telia.api-test.ruwido.com
    Login Test API.......................: https://telia.api-test.ruwido.com/rc_config/c7f585f72324/v2/meta/EDID/signal?output=base64_blob
    Teliasonera rootcva1.................: http://crl-3.trust.teliasonera.com/teliasonerarootcav1.crl
    Teliasonera Repository Trust CPS.....: http://repository.trust.teliasonera.com/CPS
    Telia OCSP Trust URL.................: http://ocsp.trust.telia.com
    Telia OCSP Trust CSP Download........: https://repository.trust.teliasonera.com/CPS
    TeliaSonera root cav1.cer cert.......: http://repository.trust.teliasonera.com/teliasonerarootcav1.cer
    TeliaSonera Server cav2.cer file.....: http://repository.trust.teliasonera.com/teliasoneraservercav2.cer
    ```

* Download and Backup your splash theme if you want to replace the splash theme during boot
* Kernel Version Example: kreatelVhi53_5_5_1_p4_220425_SWE_13852

```
http://image.iptv.telia.se/teliasonera-vip5305?product=teliasonera-vip5305&serial=<TV_BOX_SERIAL>&mac=<TV_BVOX_MAC_ADDRESS_HERE>&fw_version=7.12.2&kernel_version=<CURRENT_KERNEL_VERSION_HERE>&splash_version=5305_1
```

### Download default splash theme used from stock rom

```bash
wget2 –user-agent="KreaTVWebKit/600 (Motorola STB; Linux; 5305)" https://wpc.97697.teliacdn.net/8097697/ott/splashTheme.pkg.sec
```

### Get http.requests uri (execute on router for virtual iptv interface)

```bash
tshark -i vlan_iptv -T fields -e http.request.uri |grep \S
```

### Available urls

```
/iptvgui/ikons_1920x1080/channelIcon_0.png
/iptvgui/ikons_1920x1080/channelIcon_430.png
/iptvgui/ikons_1920x1080/channelIcon_438.png
/iptvgui/ikons_1920x1080/channelIcon_440.png
/iptvgui/ikons_1920x1080/channelIcon_444.png
/iptvgui/ikons_1920x1080/channelIcon_100.png
/iptvgui/ikons_1920x1080/channelIcon_109.png
/iptvgui/ikons_1920x1080/channelIcon_435.png
/iptvgui/ikons_1920x1080/channelIcon_463.png
/iptvgui/ikons_1920x1080/channelIcon_491.png
/iptvgui/ikons_1920x1080/channelIcon_462.png
/iptvgui/ikons_1920x1080/channelIcon_437.png
/iptvgui/ikons_1920x1080/channelIcon_471.png
/iptvgui/ikons_1920x1080/channelIcon_470.png
/iptvgui/ikons_1920x1080/channelIcon_472.png
/iptvgui/ikons_1920x1080/channelIcon_26.png
/iptvgui/ikons_1920x1080/channelIcon_445.png
/iptvgui/ikons_1920x1080/channelIcon_67.png
/iptvgui/ikons_1920x1080/channelIcon_58.png
/iptvgui/ikons_1920x1080/channelIcon_270.png
/iptvgui/ikons_1920x1080/channelIcon_777.pngtshark
/iptvgui/ikons_1920x1080/channelIcon_3063.png
/iptvgui/ikons_1920x1080/channelIcon_3064.png
/iptvgui/ikons_1920x1080/channelIcon_522.png
and alot more....
```

### Download all tv icons available from Telia:

Also available in icon folder in this repository

```bash
for icons in $(seq 0 1000); do 
  wget2 –user-agent="KreaTVWebKit/600 (Motorola STB; Linux; 5305)" \
    http://iptv-icons.telia.se/iptvgui/ikons_1920x1080/channelIcon_${icons}.png; 
done
```

We don't get any shell via serial via UART, this is all we gonna see from bootlog

### Bootlog

```bash
System memory: 2048 MB

Using Slot 1
Using two stage boot
Unpacking Image ...Done
hisilicon-pcie f0001000.pcie: missing *config* reg space
hisilicon-pcie f0001000.pcie: PCIe Link Fail
pcieport 0000:00:00.0: buffer not found in pci_save_pcie_state
starting pid 147, tty '/dev/console': '/etc/rc.sysinit'
mount: mounting none on /var/extstorage failed: No such file or directory
fb_mem=250000
insmod hi_fb.ko video="hifb:vram0_size:250000"
insmod hi_ir.ko key_fetch=1
date: can't set date: Invalid argument
Thu Jan  1 00:00:00 UTC 1970
Note: Already updated, signature is the same
/etc/rc.sysinit: line 282: can't create /proc/sys/net/ipv4/conf/eth1/force_igmp_version: nonexistent directory
chmod: /usr/bin/logapp.sh: Read-only file system
Error: Unable to read name service address from file /tmp/nameservice_address defined by NS_ADDRESS_FILENAME
```

### Reboot

* Device Restart Log

```bash
System memory: 2048 MB

Using Slot 1
Using two stage boot
Unpacking Image ...Done
hisilicon-pcie f0001000.pcie: missing *config* reg space
hisilicon-pcie f0001000.pcie: PCIe Link Fail
pcieport 0000:00:00.0: buffer not found in pci_save_pcie_state
starting pid 147, tty '/dev/console': '/etc/rc.sysinit'
mount: mounting none on /var/extstorage failed: No such file or directory
fb_mem=250000
insmod hi_fb.ko video="hifb:vram0_size:250000"
insmod hi_ir.ko key_fetch=1
date: can't set date: Invalid argument
Thu Jan  1 00:00:00 UTC 1970
Note: Already updated, signature is the same
/etc/rc.sysinit: line 282: can't create /proc/sys/net/ipv4/conf/eth1/force_igmp_version: nonexistent directory
chmod: /usr/bin/logapp.sh: Read-only file system
Error: Unable to read name service address from file /tmp/nameservice_address defined by NS_ADDRESS_FILENAME
⸮^@^@^@
Firmware
I found the source for Arris firmware, it can be found on urls below and i created this script for find the firmwares, if you are a user from another country, you can probably find your firmware also if you change "Swe" to your country, check in the menu for the device what the name of the firmware is and you will see how to find the firmware for your country.
```

!!! Warning: "Important Legal Advisory: In compliance with Swedish laws and regulations, I strongly recommend against undertaking the actions described here. Additionally, while exploring firmware versions through URL digit fuzzing (http://wpc.97697.teliacdn.net/<xxxxx>/ott/stbimage) may reveal more firmware files, please proceed with caution and respect for privacy laws. Using the specific user agent might help minimize visibility in logs, yet this does not negate the legal implications of unauthorized access or modification."

* There is customized firmware files country wise, I know for sure there are firmware files for 

```bash
Finland
Denmark
Norway
Latvia
```

```bash
#!/usr/bin/env bash

# - iNFO ----------------------------------------------------------------------------
#
#        Author: wuseman <wuseman@nr1.nu>
#      FileName: arris-firmware-hunting.sh
#       Version: 1.0
#
#       Created: 2022-12-20 (02:03:48)
#      Modified: 2022-12-20 (02:09:54)
#
#          Note: Shared for educational purposes.
#                        I take no responsibility whatsoever other users do. 
#                        Before you use my things on this website, 
#                        I remind you to read my policy/rules.
#
#
# - LiCENSE ------------------------------------------------------------------------

source="http://wpc.97697.teliacdn.net/8097697/ott/stbimage"

if [[ ! -f "~/telia-tv-firmware.log" ]]; then 
  touch ~/telia-tv-firmware.log; fi

wget2 &> /dev/null;[[ $? -ne "0" ]] && printf '%s\n' 'wget2 is reuqired ot be installed'; exit 

for version in $(seq -w 0000 9999); do
        wget2 --spider –user-agent="KreaTVWebKit/600 (Motorola STB; Linux; 5305)" \
        ${source}-${version}Swe|grep -iq "OK"
        if [[ $? = "0" ]]; then
                echo -e "[\e[1;32m+\e[0m] - Firmware found: ${source}-${version}Swe" \
                echo -e "${source}-${version}Swe" >>  ~/telia-tv-firmware.log
                                else
                echo -e "[\e[1;31m-\e[0m] - Firmware not found: ${source}-${version}Swe"
        fi
done

curl 'https://image.iptv.telia.se/teliasonera-vip5305?product=teliasonera-vip5305&serial=<serial>&mac=<mac_addr>&fw_version=7.12.2&kernel_version=<kernel>&splash_version=5305_1%20HTTP/1.1' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: KreaTVWebKit/600 (Motorola STB; Linux; 5305)' -H 'sec-ch-ua-platform: "TV Box"'
```

* Output From Above Command

```
<?xml version="1.0"?>
<!DOCTYPE StbConfig SYSTEM "stbconfig.dtd">
<StbConfig><BootParams>
  <KernelUrl>http://wpc.97697.teliacdn.net:80/8097697/ott/stbimage-5305Swe</KernelUrl>
  <KernelVersion>kreatelVhi53_5_5_1_p6_220519_SWE_13956</KernelVersion><ThemeUrl>http://wpc.97697.teliacdn.net:80/8097697/ott/splashimageSweTheme.pkg.sec</ThemeUrl>
<ThemeVersion>1.2</ThemeVersion>
</BootParams>
</StbConfig>
```


### Ramdisk Contents

The ramdisk includes the following directories and files:

```
./init
./dev
./dev/mtd
./dev/mtdblock
./dev/fb
./flash
./flash2
./etc
./lib
./lib/modules
./lib/modules/gpiomod.ko
./lib/modules/nand_ids.ko
./lib/modules/nand_ecc.ko
./lib/modules/nand.ko
./lib/modules/kreatel_nand.ko
./lib/modules/yaffs.ko
./lib/modules/kb.o
./lib/modules/front_panelmod.ko
./lib/modules/ir.o
./proc
./tmp
./root
./usr
./usr/bin
./usr/bin/ipconfig
./usr/bin/mount
./usr/bin/gunzip
./usr/bin/nuke
./usr/bin/insmod
./usr/bin/multicast
./usr/bin/tftp
./usr/bin/logger
./usr/bin/display_program
./usr/fonts
./usr/fonts/Vera.ttf
./usr/splash
```

The `init` script is responsible for most tasks in the second-stage bootloader, including the ability to download new software to the NAND flash.

## Decrypting the Firmware

The firmware uses AES-256 encryption in ECB mode. The key for decryption, used for both the second-stage bootloader and the NAND software, is stored in encrypted form in the hardware chip.

### Decryption / Extraction Program Written in `c`

Below is a simple program demonstrating how to decrypt both encrypted images:

```bash
/********************************************************************************
 * Program: AES ECB Mode Decryption Utility
 * Author: wuseman 
 * License: WTFTL ( https://en.wikipedia.org/wiki/WTFPL ) 
 * Description:
 *     This program decrypts a file using AES encryption in ECB mode.
 *     It is designed as an example and should not be used in production
 *     environments due to ECB mode's security vulnerabilities.
 *
 * Usage:
 *     motorola-arris-decryptor <input file> <output file> <offset>
 *
 * Note:
 *     This program uses OpenSSL for cryptographic operations.
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int decrypt_aes_ecb(const unsigned char *key, const char *input_filename, const char *output_filename, long offset) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    FILE *input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "Failed to open input file: %s\n", input_filename);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        fprintf(stderr, "Failed to open output file: %s\n", output_filename);
        fclose(input_file);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    fseek(input_file, offset, SEEK_SET);
    unsigned char in[16], out[16 + EVP_MAX_BLOCK_LENGTH];
    int out_len;
    size_t read_bytes;
    while ((read_bytes = fread(in, 1, sizeof(in), input_file)) > 0) {
        if (EVP_DecryptUpdate(ctx, out, &out_len, in, read_bytes) != 1) {
            fprintf(stderr, "Decryption error\n");
            break;
        }
        fwrite(out, 1, out_len, output_file);
    }

    if (EVP_DecryptFinal_ex(ctx, out, &out_len) != 1) {
        fprintf(stderr, "Final decryption error\n");
    } else {
        fwrite(out, 1, out_len, output_file);
    }

    fclose(input_file);
    fclose(output_file);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <input file> <output file> <offset>\n", argv[0]);
        return -1;
    }

    const unsigned char key[] = {0x35, 0x24, 0x79, 0xec, 0xce, 0xf2, 0xf1, 0xe8, 
                                 0x58, 0x8e, 0x93, 0x5c, 0x26, 0xc3, 0xa1, 0x15,
                                 0x2b, 0x43, 0x3f, 0x86, 0xbd, 0x1e, 0xd3, 0x15, 
                                 0xcc, 0x1c, 0xed, 0x16, 0xc4, 0x67, 0x5c, 0xa2};

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    long offset = strtol(argv[3], NULL, 0);

    if (decrypt_aes_ecb(key, input_filename, output_filename, offset) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }

    printf("Decryption completed successfully.\n");
    return 0;
}

```
