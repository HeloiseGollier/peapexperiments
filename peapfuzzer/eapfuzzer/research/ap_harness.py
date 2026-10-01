#!/usr/bin/env python3
import time

from OpenSSL import SSL
import socket
import os
import subprocess
from wpaspy import Ctrl

from libwifi.field_ckecker import *
from scapy.layers.eap import EAP, EAPOL
from libwifi.eap_peap import EapMethod_Peap, tls_bio_read, tls_read
from libwifi import *
from libwifi import mschap
import four_way

from config import CONFIG

EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
__EAP_TYPE_MIN_METHOD = 4
EAP_TYPE_TLS = 13
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26
EAP_TYPE_MS_AUTH_TLV = 33

EAPOL_TYPE_START = 1
EAPOL_TYPE_KEY = 3

TLS_HEADER_LENGTH = 5
TLS_TYPE_ALERT = 21
TLS_TYPE_APPLICATION_DATA = 23

llHOST = CONFIG["learnlib_host"]
llPORT = CONFIG["learnlib_port"]
learnlib_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

CLIENT_HOST = CONFIG["client_host"]
CLIENT_PORT = CONFIG["client_port"]
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def hostapd_read_config(config):
    # Read the config and get the interface name
    interface = None
    with open(config) as fp:
        for line in fp.readlines():
            line = line.strip()
            if line.startswith("interface="):
                interface = line.split('=')[1]

    return interface


class HostApd:
    def __init__(self):
        # Parse hostapd.conf
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        try:
            interface = hostapd_read_config(os.path.join(self.script_path, "conffiles/hostapd.conf"))
        except Exception as ex:
            log(ERROR, "Failed to parse the hostapd.conf config file")
            raise
        if not interface:
            log(ERROR,
                'Failed to determine wireless interface. Specify one in hostapd.conf at the line "interface=NAME".')
            quit(1)

        # Set other variables
        self.stations = dict()
        self.nic_iface = interface
        try:
            self.apmac = scapy.arch.get_if_hwaddr(interface)
        except:
            log(ERROR,
                'Failed to get MAC address of %s. Specify an existing interface in hostapd.conf at the line '
                '"interface=NAME".' % interface)
            raise

        # Open our modified hostapd build
        try:
            self.hostapd = subprocess.Popen([
                                                os.path.join(self.script_path, "../hostapd/hostapd"),
                                                os.path.join(self.script_path, "conffiles/hostapd.conf")]
                                            + ["-i" + CONFIG["interface"]])
        except:
            if not os.path.exists("../hostapd/hostapd"):
                log(ERROR, "hostapd executable not found. Did you compile hostapd?")
            raise
        time.sleep(2)

        try:
            self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_iface)
            self.hostapd_ctrl.attach()
        except:
            log(ERROR, "It seems hostapd did not start properly, please inspect its output.")
            log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise hostapd won't work.")
            raise

        # Enable interception and modification of Association frames
        self.hostapd_ctrl.request("SET ext_assoc_frame_override 1")
        # Enable interception and custom handling of EAP frames
        self.hostapd_ctrl.request("SET ext_eapol_frame_io 1")
        # self.hostapd_ctrl.request("SET ext_mgmt_frame_handling 1")

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()

    def wait_event(self, events, timeout):
        start = os.times()[4]
        while True:
            while self.hostapd_ctrl.pending():
                ev = self.hostapd_ctrl.recv()
                for event in events:
                    if event in ev:
                        if event == "MGMT-RX":
                            if ((ev.split()[1][20:32] == client_address)
                                    and (ev.split()[1][0:4] in ("a000", "c000"))):
                                return ev
                            else:
                                continue
                        else:
                            return ev
            now = os.times()[4]
            remaining = start + timeout - now
            if remaining <= 0:
                break
            if not self.hostapd_ctrl.pending(timeout=remaining):
                break
        return None



def connect(sock, host, port):
    print("trying to connect to client...")
    print(host + ":" + str(port))
    sock.connect((host, port))


def listen(sock):
    data = None
    while data is None or len(data) == 0:
        data = sock.recv(1024)
    log(STATUS, "Got " + data.decode(), "green")
    return data.decode()


def send(sock, data):
    log(STATUS, "Sending " + data, "green")
    sock.sendall(data.encode())


def reset_client():
    send(client_sock, "rst\n")


def build_id_request(pkt_id):
    eap = EAP(code=EAP.REQUEST, id=pkt_id, type='Identity')
    return eap


def send_eapol(pkt):
    data = raw(pkt).hex()
    print("In send_eapol")
    print(data)
    hostapd.hostapd_ctrl.request("EAPOL_TX %s %s" % (client_address, data))


class Eap:
    RESETTING, DOING_PEAP, READY_FOR_INNER_TUNNEL = range(3)


    def __init__(self):
        self.pkt_id = 103
        self.state = self.RESETTING
        self.peap = EapMethod_Peap(self.pkt_id)

    def send_eapol_id_request(self):
        """EAP Identity Request"""
        eap = build_id_request(self.pkt_id)
        eapol = EAPOL(version="802.1X-2004", type="EAP-Packet") / eap

        log(STATUS, "%s: sending EAP identity request" % client_address)
        send_eapol(eapol)

    def handle_assoc_tx(self, ev):
        data = ev.split()[1]
        p = Dot11(binascii.unhexlify(data))

        self.send_mgmt(p)

    def send_mgmt(self, pkt):
        data = raw(pkt).hex()
        hostapd.hostapd_ctrl.request("MGMT_TX %s" % data)

    def handle_legacy_nak(self, eapol):
        log(STATUS,
            "%s: recieved NAK, client requesting auth types %s" % (client_address, eapol[EAP].desired_auth_types))

    def eap_handle(self, eap):
        # Let the EAP class handle the message.
        self.peap.process(eap,client_address)

    def eap_send_next(self):
        peap = self.peap.build_req(client_address)
        if peap is None:
            log(WARNING, "%s: Outer Handshake Completed" % client_address)
            if self.peap.state == self.peap.COMPLETED:
                self.state = self.READY_FOR_INNER_TUNNEL
            return

        eapol = EAPOL(version="802.1X-2004", type="EAP-Packet") / peap
        send_eapol(eapol)

    def handle_eapol(self, ev):
        addr = ev.split()[1]
        data = ev.split()[2]
        eapol = EAPOL(binascii.unhexlify(data))
        print("got this from client:")
        print(repr(eapol))

        if not EAP in eapol:
            log(WARNING, "Received EAPOL frame without EAP payload")
            return

        # Special cases: EAP Identity and Legacy NAK
        if eapol[EAP].type == EAP_TYPE_IDENTITY:
            self.eap_send_next()
        elif eapol[EAP].type == EAP_TYPE_NAK:
            self.handle_legacy_nak(eapol)
        elif eapol[EAP].id != self.peap.msg_id:
            print(str(eapol[EAP].id) + " vs " + str(self.peap.msg_id))
        # Continue normal EAP operation
        else:
            self.eap_handle(eapol[EAP])
            self.eap_send_next()

    def execute_peap_handshake(self):
        while True:
            ev = hostapd.wait_event(["NEW-STA", "EAPOL-RX", "ASSOC-TX"], timeout=10)
            if ev is None:
                log(STATUS, "Client stopped responding, rebooting it...", color="red")
                self.peap = EapMethod_Peap(self.pkt_id)
                self.state = self.RESETTING
                reset_client()
                continue
            print(ev)

            if "NEW-STA" in ev:
                # Handle associated client and start EAP handshake
                global client_address
                client_address = ev.split(" ")[1].replace(":", "")
                self.send_eapol_id_request()
            elif "ASSOC-TX" in ev:
                # Allow modification of Information Elements in the association response
                self.handle_assoc_tx(ev)
                self.state = self.DOING_PEAP
            elif "EAPOL-RX" in ev:
                # Handle received EAPOL frames from the client
                self.handle_eapol(ev)
                if self.state == self.READY_FOR_INNER_TUNNEL:
                    return


class Fuzzer:
    # LearnLib specific requests
    reset = "rst"

    # Inner tunnel layer requests for the client
    id_request = "id_request_v0"
    challenge = "challenge_v0"
    success_request = "success_request_v0"
    success_request_with_credentials = "success_request_with_credentials_v0"
    success_request_wrong_password = "success_request_all_zeros_v0"
    success_and_cryptobinding = "success_and_cryptobinding"
    cryptobinding = "cryptobinding"
    success = "tlv_request"
    failure = "tlv_failure"
    anonymous_identity = "tlv_anonymous"

    # eapol layer requests for the client
    eap_success = "eap_success"
    four_way_message_1 = "4_way_message_1"

    # Responses
    # Inner tunnel.
    id_response = "id_response_v0"
    challenge_response = "challenge_response_v0"
    success_response = "success_response_v0"
    tlv_success = "tlv_success"
    tlv_success_and_cryptobinding = "tlv_success_and_cryptobinding"
    tlv_failure = "tlv_failure"
    tlv_cryptobinding = "tlv_cryptobinding"
    empty_peap = "empty_peap"
    nak = "nak"


    # PEAP version 1 messages
    id_request_v1 = "id_request_v1"
    challenge_request_v1 = "challenge_v1"
    success_request_v1 = "success_request_v1"
    success_request_with_credentials_v1 = "success_request_with_credentials_v1"
    success_request_wrong_password_v1 = "success_request_all_zeros_v1"
    inner_success = "inner_success"
    inner_failure = "inner_failure"

    id_response_v1 = "id_response_v1"
    challenge_response_v1 = "challenge_response_v1"
    success_response_v1 = "success_response_v1"
    inner_success_response = "inner_success_response"
    inner_failure_response = "inner_failure_response"

    # TLS layer
    encrypted_alert = "encrypted_alert"
    tls_bad_cipher_exception = "tls_bad_cipher_exception"

    # EAPOL layer
    four_way_message_2 = "4_way_message_2"

    # No reply
    no_reply = "no_reply"
    no_reply_after_eap_success = "after_eap_success"

    # 802.11 layer packets
    disassociation = "disassociation"
    deauthentication = "deauthentication"

    def __init__(self, eap):
        self.eap = eap
        self.outer_tunnel = eap.peap
        self.tls = self.outer_tunnel.tls
        self.pkt_id = self.outer_tunnel.msg_id
        self.pmk = self.tls.export_keying_material("client EAP encryption".encode('ascii'), 60)
        self.four_way_hs = four_way.FourWayHandshake(client_address, hostapd, self.pmk[0:32])
        self.mschap_hs = EapMethod_MsChap(pkt_id=self.pkt_id, pmk=self.pmk)
        self.sent_eap_success = False

    def send(self, response):
        send(learnlib_sock, response + "\n")

    def fuzz(self):
        # Be able to detect deauthentication frames
        hostapd.hostapd_ctrl.request("SET ext_mgmt_frame_handling 1")

        while True:
            self.pkt_id += 1

            # Get instruction from learnlib
            data = listen(learnlib_sock)

            if data == self.reset:
                hostapd.hostapd_ctrl.request("SET ext_mgmt_frame_handling 0")
                reset_client()
                self.send("Done.")
                return

            ready_packet = self.build_packet(data)

            # Send packet to client
            send_eapol(ready_packet)

            # Wait for response from client
            ev = hostapd.wait_event(["EAPOL-RX", "MGMT-RX"], timeout=0.1)
            if ev is None:
                if self.sent_eap_success:
                    self.send(self.no_reply_after_eap_success)
                else:
                    self.send(self.no_reply)
                self.sent_eap_success = False
                continue
            elif "MGMT-RX" in ev:
                print("Management frame? " + ev)
                if is_deauth(ev):
                    self.send(self.deauthentication)
                else:
                    assert (is_disass(ev))
                    self.send(self.disassociation)
                continue

            data = ev.split()[2]
            resp = self.unpack_packet(data)
            self.send(resp)

    def build_packet(self, command):
        # Already handle EAP layer requests here
        if command == self.four_way_message_1:
            time.sleep(0.1)
            return self.four_way_hs.build_eapol_1_key()
        elif command == self.eap_success:
            self.sent_eap_success = True
            return EAPOL(version="802.1X-2004", type="EAP-Packet") / EAP(code="Success", id=self.pkt_id)

        ready_message = self.mschap_hs.build_req(command, self.pkt_id)
        self.tls.write(raw(ready_message))

        try:
            encrypted = tls_bio_read(self.tls)
        except SSL.Error as e:
            for lib, func, reason in e.errors:
                print(f"Library: {lib}, Function: {func}, Reason: {reason}")
            raise e

        assert len(encrypted) > 0

        self.outer_tunnel.enqueue_tls_data(encrypted)
        encrypted = self.outer_tunnel.build_tx_tls_data(self.pkt_id)
        return EAPOL(version="802.1X-2004", type="EAP-Packet") / encrypted

    def unpack_packet(self, data):
        eapol = EAPOL(binascii.unhexlify(data))
        print("Received EAPOL: " + repr(eapol))

        if eapol.type == EAPOL_TYPE_KEY:
            return self.four_way_hs.process_eapol_key(eapol)
        if not EAP in eapol:
            assert 0

        eap_msg = eapol[EAP]
        tls_data = eap_msg.tls_data

        # Pass any incoming data to the TLS object
        if len(tls_data) > 0:
            print("Parsing tls data")
            tls_message_length = tls_data[3:5]
            print(" ".join(f"{b:02x}" for b in tls_data[3:5]))
            print(int.from_bytes(tls_message_length, "big"))
            total_message_length = TLS_HEADER_LENGTH + int.from_bytes(tls_message_length, "big")
            print(total_message_length)
            messages = ""
            print(len(tls_data))
            while len(tls_data) >= total_message_length:
                # Multiple EAP messages
                messages += self.process_tls_payload(tls_data[0:total_message_length])
                print("messages so far:" + messages)

                tls_data = tls_data[total_message_length:]
                print(" ".join(f"{b:02x}" for b in tls_data))

                tls_message_length = tls_data[3:5]
                print("message length: " + " ".join(f"{b:02x}" for b in tls_message_length))
                print(int.from_bytes(tls_message_length, "big"))
                total_message_length = TLS_HEADER_LENGTH + int.from_bytes(tls_message_length, "big")
            return messages

        else:
            return self.empty_peap

    def process_tls_payload(self, tls_payload):
        if int.from_bytes(tls_payload[0:1], "big") == TLS_TYPE_ALERT:
            return self.encrypted_alert

        self.tls.bio_write(tls_payload)

        try:
            unencrypted = tls_read(self.tls)
            print("Unencrypted TLS payload" + " ".join(f"{b:02x}" for b in unencrypted))
        except SSL.Error as e:
            if "cipher operation failed" in str(e) or "Unexpected EOF" in str(e):
                print("Caught bad cipher exception")
                return self.tls_bad_cipher_exception
            else:
                raise e

        return self.mschap_hs.process(unencrypted)


class EapMethod_MsChap:
    null_authenticator_response = b''.fromhex("00") * 20
    correct_id_client = b"user"

    def __init__(self, pkt_id, pmk):
        self.eap_id = pkt_id
        self.pmk = pmk

        # Default values
        self.nt_response = b''.fromhex('00') * 24
        self.id_server = "eapfuzzer"
        self.auth_challenge = b''.fromhex('00') * 16
        self.password = "password"
        self.id_client = b''.fromhex('00') * 16
        self.peer_challenge = b''.fromhex('00') * 16
        self.isk = b''.fromhex('00') * 32

    def build_req(self, action, msg_id):
        self.eap_id = msg_id
        log(STATUS, "Inner Tunnel " + action, "green")

        #if action == Fuzzer.id_request:
        if action.startswith("id_request"):
            resp = build_id_request(self.eap_id)
            #return bytes(id_req)[4:]
        elif action.startswith("challenge"):
            resp = self.build_challenge()
            #return bytes(challenge)[4:]
        elif action == Fuzzer.success_request or action == Fuzzer.success_request_v1:
            response = mschap.generate_authenticator_response(self.password, self.nt_response, self.peer_challenge,
                                                              self.auth_challenge, self.id_client)
            resp = self.build_success_request(response)
            #return bytes(success_req)[4:]
        elif action == Fuzzer.success_request_with_credentials or action == Fuzzer.success_request_with_credentials_v1:
            self.nt_response = mschap.generate_nt_response_mschap2(self.auth_challenge, self.peer_challenge,
                                                                   self.correct_id_client, self.password)
            response = mschap.generate_authenticator_response(self.password, self.nt_response, self.peer_challenge,
                                                              self.auth_challenge, self.correct_id_client)
            resp = self.build_success_request(response)
            #return bytes(success_req)[4:]
        elif action == Fuzzer.success_request_wrong_password or action == Fuzzer.success_request_wrong_password_v1:
            resp = self.build_success_request(self.null_authenticator_response)
            #return bytes(success_req)[4:]
        else:
            tlv_success = b''.fromhex("80 03 00 02 00 01")
            tlv_failure = b''.fromhex("80 03 00 02 00 02")
            tlv_crypto = self.build_cryptobinding_tlv()
            eap_header = EAP(code=EAP.REQUEST, id=self.eap_id, type=EAP_TYPE_MS_AUTH_TLV)
            if action == Fuzzer.anonymous_identity:
                tlv_anonymous = self.build_anonymous_id_tlv()
                return eap_header / Raw(tlv_success + tlv_crypto + tlv_anonymous)
            elif action == Fuzzer.success_and_cryptobinding:
                return eap_header / Raw(tlv_success + tlv_crypto)
            elif action == Fuzzer.cryptobinding:
                return eap_header / Raw(tlv_crypto)
            elif action == Fuzzer.success:
                return eap_header / Raw(tlv_success)
            elif action == Fuzzer.failure:
                return eap_header / Raw(tlv_failure)
            elif action == Fuzzer.inner_success:
                log(STATUS, "MSChapv2 sending done", "green")
                return EAP(code="Success", id=self.eap_id)
            elif action == Fuzzer.inner_failure:
                return EAP(code="Failure", id=self.eap_id)
            else:
                assert 0
        if "v0" in action:
            return bytes(resp)[4:]
        else:
            return resp


    def process(self, eapdata):
        if len(eapdata) == 0:
            return Fuzzer.empty_peap

        if eapdata[0] == 2 and (EAP(eapdata).type == EAP_TYPE_MSCHAPV2 or EAP(eapdata).type == EAP_TYPE_IDENTITY): # version 1 messages
            eap = EAP(eapdata)
            if eap[EAP].type == EAP_TYPE_IDENTITY:
                # Handle EAP identity frame
                self.id_client = eap[EAP].identity
                return Fuzzer.id_response_v1
            # Note: client should mirror the mschapv2_id of the request
            else:
                if len(eap.load) >= 4:
                    assert is_challenge_response_v1(eap)
                    remaining = eap.load[4:]
                    self.handle_response(remaining)
                    return Fuzzer.challenge_response_v1

                else:
                    assert is_success_response_v1(eap)
                    return Fuzzer.success_response_v1

        elif eapdata[0] == EAP_TYPE_NAK and eapdata[1] == 26:
            print(eapdata)
            return Fuzzer.nak

        if eapdata[0] == EAP_TYPE_IDENTITY:
            # Handle EAP identity frame
            self.id_client = eapdata[1:]
            return Fuzzer.id_response

        elif eapdata[0] == EAP_TYPE_MSCHAPV2:
            if len(eapdata[1:]) >= 4:
                assert is_challenge_response(eapdata)
                remaining = eapdata[5:]
                self.handle_response(remaining)
                return Fuzzer.challenge_response

            else:
                assert is_success_response(eapdata)
                return Fuzzer.success_response

        eap = EAP(eapdata)
        print(repr(eap))
        if eap.type == EAP_TYPE_MS_AUTH_TLV:
            if is_tlv_success(eap):
                if len(eap.load) > 6:
                    assert len(eap.load) == 66
                    print(eap.load[6:8])
                    assert eap.load[6:8] == b''.fromhex("00 0c")
                    return Fuzzer.tlv_success_and_cryptobinding
                else:
                    assert len(eap.load) == 6
                    return Fuzzer.tlv_success
            elif is_tlv_failure(eap):
                return Fuzzer.tlv_failure
            else:
                assert is_tlv_cryptobinding(eap)
                return Fuzzer.tlv_cryptobinding
        elif eap.code == 3:
            assert len(eap) == 4
            return Fuzzer.inner_success_response
        elif eap.code == 4:
            assert len(eap) == 4
            return Fuzzer.inner_failure_response
        else:
            assert 0

    def build_eap_ms_header(self):
        return EAP(code=EAP.REQUEST, id=self.eap_id, type='MS-EAP-Authentication')

    def build_challenge(self):
        self.auth_challenge = b"0123456789ABCDEF"
        op_code = 1
        mschapv2_id = 2  # XXX must be incremented in new attempts
        ms_length = 5 + len(self.auth_challenge) + len(str2bytes(self.id_server))
        mschapdata = struct.pack(">BBHB", op_code, mschapv2_id, ms_length, len(self.auth_challenge))
        mschapdata += self.auth_challenge
        mschapdata += str2bytes(self.id_server)
        return self.build_eap_header() / Raw(mschapdata)

    def handle_response(self, mschapdata):
        value_size = mschapdata[0]
        self.peer_challenge = mschapdata[1:17]
        reserved = mschapdata[17:25]
        self.nt_response = mschapdata[25:49]
        flags = mschapdata[49]
        name = mschapdata[50:]  # XXX --- Is this the inner authentication username?

        expected_response = mschap.generate_nt_response_mschap2(self.auth_challenge, self.peer_challenge,
                                                                self.id_client, self.password)
        log(STATUS,
            "%s MS-Chap: received expected nt_response %d" % (
                client_address, self.nt_response == expected_response))
        self.isk = mschap.mschapv2_get_key(self.password, self.nt_response)

    def build_success_request(self, response):
        auth_resp = b"S=" + binascii.hexlify(response).upper()
        auth_resp += b" M=OK"

        op_code = 3
        mschapv2_id = 3  # XXX must be incremented in new attempts
        ms_length = 4 + len(auth_resp)
        mschapdata = struct.pack(">BBH", op_code, (mschapv2_id - 1), ms_length)
        mschapdata += str2bytes(auth_resp)
        print(mschapdata)
        return self.build_eap_header() / Raw(mschapdata)

    def build_cryptobinding_tlv(self):
        icmk = mschap.peap_prfplus(self.pmk[0:40], "Inner Methods Compound Keys".encode() + self.isk, 60)

        cmk = icmk[40:60]

        crypto_tlv_header = b''.fromhex("00 0c 00 38 00 00 00 00")
        nonce = b''.fromhex("0e 65 cf 3c 3f 86 18 da bd f0 2e 2f 91 07 c7 84 84 77 87 28 c7 92 70 01 "
                            "4f d5 b0 9e 0b 28 8b c0")

        compound_data = crypto_tlv_header + nonce + (b''.fromhex("00") * 20) + b''.fromhex("19")

        compound_mac = mschap.derive_compound_mac(compound_data, cmk)

        crypto_tlv = crypto_tlv_header + nonce + compound_mac
        return crypto_tlv

    def build_anonymous_id_tlv(self):
        id_tlv_type = b''.fromhex("00 15")
        anonymous_id = b'thisisananonymousid'
        length = b''.fromhex(format(len(anonymous_id), '04x'))
        identity_tlv = id_tlv_type + length + anonymous_id
        print(identity_tlv)
        return identity_tlv

    def build_eap_header(self):
        return EAP(code=EAP.REQUEST, id=self.eap_id, type='MS-EAP-Authentication')



def cleanup():
    hostapd.stop()


def main():
    global hostapd

    hostapd = HostApd()
    atexit.register(cleanup)

    connect(learnlib_sock, llHOST, llPORT)
    connect(client_sock, CLIENT_HOST, CLIENT_PORT)

    while True:
        try:
            eap = Eap()
            eap.execute_peap_handshake()

            fuzzer = Fuzzer(eap)
            fuzzer.fuzz()
        except AssertionError as e:
            print(e)


if __name__ == "__main__":
    main()
