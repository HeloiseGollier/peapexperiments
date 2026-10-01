from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11EltVendorSpecific

from libwifi.key_eapol import EAPOL_KEY
from libwifi import *
import binascii, struct
from scapy.layers.eap import EAPOL


class FourWayHandshake:
    four_way_message_1 = "4_way_message_1\n"
    four_way_message_3 = "4_way_message_3\n"

    four_way_message_2 = "4_way_message_2\n"
    four_way_message_4 = "4_way_message_4\n"

    def __init__(self, addr, hostapd, pmk):
        self.mac = scapy.arch.get_if_hwaddr(hostapd.nic_iface)
        self.pmk = pmk

        self.clientmac = addr
        self.ptk = None

        self.snonce = b''.fromhex(
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.anonce = b''.fromhex(
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.replay_counter = 0

    def process(self, msg):
        if WPA_key in msg and msg[WPA_key].wpa_key_length == 0:
            log(STATUS, "Received message 4, handshake complete!")
            return self.four_way_message_4
        else:
            # TODO: Better checks
            self.process_eapol_2_key(msg)
            return self.four_way_message_2

    def build_req(self, cmd):
        if cmd == self.four_way_message_1:
            return self.build_eapol_1_key()
        elif cmd == self.four_way_message_3:
            return self.build_eapol_3_key()
        else:
            assert 0

    def build_first_key(self):
        self.anonce = b''.fromhex(
            "55 63 33 6e 02 d7 74 3c 41 c0 9b 0e 1b 59 a1 b5 1c a4 56 f0 bb 90 74 51 1b 03 49 e3 7c 0d 31 0b")
        key = EAPOL_KEY(key_descriptor_type=2, res2=0, smk_message=0,
                        encrypted_key_data=0, request=0, error=0, secure=0,
                        has_key_mic=0, key_ack=1, install=0, res=0, key_type=1,
                        key_descriptor_type_version=2, len=16, key_replay_counter=1,
                        key_nonce=self.anonce, key_iv=0, key_rsc=b'', key_id=b'', key_mic=b'', key_length=0,
                        key=None)
        return key

    def start_handshake(self, msg):
        log(STATUS, "Message:" + repr(msg), color="green")
        self.clientmac = self.clientmac
        log(STATUS, f"Starting handshake with {self.clientmac}")

        return self.build_eapol_1_key()

    def build_eapol_1_key(self):
        """First Message of 4-way Handshake"""
        key = self.build_first_key()
        eapol = EAPOL(version="802.1X-2004", type="EAPOL-Key") / key

        return eapol

    # https://github.com/domienschepers/wifi-framework/blob/master/test-4wayhs.py
    def process_eapol_2_key(self, msg):
        self.snonce = msg[WPA_key].nonce
        log(STATUS, f"Received snonce {self.snonce}")

        self.derive_ptk()

        eapol = msg[EAPOL].copy()
        eapol.wpa_key_mic = b"\x00" * 20
        mic = hmac.new(self.ptk[0:16], bytes(eapol), hashlib.sha1).digest()[0:16]
        log(STATUS, f"Calculated MIC: {mic}")
        log(STATUS, f"Received MIC:   {msg[EAPOL].wpa_key_mic}")

    def build_eapol_3_key(self):
        """Third Message of 4-way Handshake"""

        self.replay_counter += 1

        # TODO Get the RSNE from hostap
        rsne = b''.fromhex("30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 01 00 00")

        # Get GTK from Hostapd so it's of the correct length in all cases
        gtk = b''.fromhex("5b 04 c2 7d e4 18 f3 13 49 a7 9e d3 4b 2d 4a ec")
        gtk_index = 1

        # See Figure 12-36—GTK KDE format:
        # - The first byte is: Key ID (2 bits), Tx (1 bit), Reserved (3 bits)
        # - The second byte is Reserved (8 bits)
        gtk_info = struct.pack(">B", gtk_index) + b"\x00"
        key_data = bytes(Dot11EltVendorSpecific(oui=0x000fac, info=b"\x01" + gtk_info + gtk))
        key_data += rsne

        if self.ptk is None:
            self.derive_ptk()
        # Encrypt the key data
        kekkey = self.ptk[16:32]
        log(STATUS, f"KEK Key:   {kekkey}")
        log(STATUS, f"Plaintext: {key_data}")
        ciphertext = aes_wrap_key_withpad(kekkey, key_data)
        log(STATUS, f"ciphertext: {ciphertext}")

        eapol = WPA_key(descriptor_type=2,
                        key_info=0x13CA,
                        len=len(gtk),
                        replay_counter=struct.pack(">Q", self.replay_counter),
                        nonce=self.anonce,
                        wpa_key_length=len(ciphertext),
                        wpa_key=ciphertext)
        eapol = EAPOL(version="802.1X-2004", type="EAPOL-Key") / eapol
        eapol.wpa_key_mic = hmac.new(self.ptk[0:16], bytes(eapol), hashlib.sha1).digest()[0:16]

        p = LLC() / SNAP() / eapol

        log(STATUS, f"Sending frame {repr(p)}")
        return eapol

    def process_eapol_key(self, msg):
        if WPA_key in msg and msg[WPA_key].wpa_key_length == 0:
            log(STATUS, "Received message 4, handshake complete!")
            return self.four_way_message_4
        else:
            self.process_eapol_2_key(msg)
            return self.four_way_message_2

    def derive_ptk(self):
        log(STATUS, "PMK: " + raw(self.pmk).hex())

        apmac = binascii.a2b_hex(self.mac.replace(":", ""))
        stamac = binascii.a2b_hex(self.clientmac.replace(":", ""))
        apnonce = self.anonce
        stanonce = self.snonce
        label = b"Pairwise key expansion"
        key_data = min(apmac, stamac) + max(apmac, stamac) + min(apnonce, stanonce) + max(apnonce, stanonce)

        self.ptk = rsn_prf_sha1(self.pmk, label, key_data, 512 // 8)[:-16]
        log(STATUS, "PTK: " + raw(self.ptk).hex())
