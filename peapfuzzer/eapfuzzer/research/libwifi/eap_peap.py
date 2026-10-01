#!/usr/bin/env python3

from . import *
from OpenSSL import SSL
import struct
from scapy.layers.eap import EAP
from config import CONFIG

EAP_TYPE_PEAP = 25


def tls_init():
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_session_cache_mode(SSL.SESS_CACHE_OFF)

    ctx.set_passwd_cb(lambda x, y, z: b"whatever")
    ctx.use_certificate_file('certs/server.pem')  # .crt
    ctx.use_privatekey_file('certs/server.key')

    tls = SSL.Connection(ctx)
    tls.set_accept_state()
    return tls


def tls_continue_handshake(tls):
    is_handshake_done = True

    try:
        tls.do_handshake()
    except SSL.WantReadError:
        is_handshake_done = False

    return is_handshake_done


def tls_bio_read(tls):
    response = bytearray()
    while True:
        try:
            response += tls.bio_read(32768)
        except SSL.WantReadError:
            break
    return response


def tls_read(tls):
    received = bytearray()
    while True:
        try:
            received += tls.read(32768)
        except SSL.WantReadError:
            break
    return received


class EapMethod_Peap:
    TYPE = EAP_TYPE_PEAP
    START_HANDSHAKE, DOING_HANDSHAKE, SEND_DATA, COMPLETED = range(4)

    def __init__(self, msg_id):
        self.state = EapMethod_Peap.START_HANDSHAKE
        self.success = False
        self.msg_id = msg_id

        self.version = CONFIG["peap_version"]

        self.tls = tls_init()
        self.tls_tx_queue = b""
        self.tls_tx_fragmenting = False

    def build_req(self,sta_addr):
        self.msg_id += 1
        # If there is (remaining) TLS data, then send it first
        self.tls_tx_queue += tls_bio_read(self.tls)
        if len(self.tls_tx_queue) > 0:
            return self.build_tx_tls_data(self.msg_id)

        # Otherwise, handle start of handshake, and handle phase2 data
        # send inside the PEAP tunnel.
        if self.state == EapMethod_Peap.START_HANDSHAKE:
            return self.build_start_handshake(sta_addr)
        elif self.state == EapMethod_Peap.DOING_HANDSHAKE:
            # Handshake TX is handled by sending pending TLS data at the
            # top of this function. So this should never be reached.
            assert 0
            # Interruption of previous session => should reset

        elif self.state == EapMethod_Peap.SEND_DATA:
            self.state = self.COMPLETED

    def process(self, eap, sta_addr):
        print(repr(eap))
        tls_data = eap.tls_data

        # If we are currently sending a fragmented TLS record, handle ACKs of fragmented TLS records
        if len(self.tls_tx_queue) > 0 and len(tls_data) == 0:
            # For an ACK frame, the flags Length, More Fragments, and Start should be zero
            assert eap.L == 0 and eap.M == 0 and eap.S == 0
            log(STATUS, "%s: received ACK to fragmented TLS record" % sta_addr)
            return
        assert eap.M == 0 and eap.S == 0, "Fragmented TLS data from client not supported"

        # Pass any incoming data to the TLS object
        if len(tls_data) > 0:
            self.tls.bio_write(tls_data)

        # Now check the TLS object: did we complete the handshake?
        if self.state <= EapMethod_Peap.DOING_HANDSHAKE:
            log(STATUS, "%s: continuing TLS handshake" % sta_addr)
            if tls_continue_handshake(self.tls):
                self.state = EapMethod_Peap.SEND_DATA

    def is_success(self):
        return self.success

    def build_start_handshake(self, sta_addr):
        # Tell client to start TLS handshake
        # if self.version == 0:
        #     tls = struct.pack(">B", 0x20)
        # else:
        #     tls = struct.pack(">B", 0x21)
        flags = 0x20 + self.version
        tls = struct.pack(">B", flags)
        eap = EAP(code=EAP.REQUEST, id=self.msg_id, type='PEAP') / Raw(tls)
        log(STATUS, "%s: sending PEAP start request" % sta_addr)
        self.state = EapMethod_Peap.DOING_HANDSHAKE
        return eap

    def build_tx_tls_data(self, msg_id):
        """
        Build an EAP frame that contains TLS data to be sent. The data is taken
        from self.tls_tx_queue and the response will be fragmented over multiple
        EAP packets if it's too big to fit into a single EAP packet.
        """

        # This is the last fragment, or a single EAP frame that contains everything
        if len(self.tls_tx_queue) <= 1300:
            # if self.version == 0:
            #     flags = 0x00  # Version 0
            # else:
            #     flags = 0x01  # Version 1
            flags = 0x00 + self.version
            tls = struct.pack(">B", flags)
            tls += self.tls_tx_queue
            self.tls_tx_queue = b""
            self.tls_tx_fragmenting = False

        # More fragments will follow, and this is the first fragment
        elif not self.tls_tx_fragmenting:
            # if self.version == 0:
            #     flags = 0xC0  # Length included, More fragments, Version 0
            # else:
            #     flags = 0xC1  # Length included, More fragments, Version 1
            flags = 0xC0 + self.version
            tls = struct.pack(">BI", flags, len(self.tls_tx_queue))
            tls += self.tls_tx_queue[:1300]
            self.tls_tx_queue = self.tls_tx_queue[1300:]
            self.tls_tx_fragmenting = True

        # More fragments will follow, this is not the first fragment
        else:
            # if self.version == 0:
            #     flags = 0x40  # More fragments, Version 0
            # else:
            #     flags = 0x41  # More fragments, Version 1
            flags = 0x40 + self.version
            tls = struct.pack(">B", flags)
            tls += self.tls_tx_queue[:1300]
            self.tls_tx_queue = self.tls_tx_queue[1300:]

        eap = EAP(code=EAP.REQUEST, id=msg_id, type='PEAP') / Raw(tls)
        log(STATUS, "%s: transmitting TLS reply")
        return eap

    def enqueue_tls_data(self, tls_data):
        """
        Enqueue new TLS response data to be sent. The previous TLS response data
        must first be sent completely and this will be checked first.
        """

        assert len(self.tls_tx_queue) == 0
        assert not self.tls_tx_fragmenting
        self.tls_tx_queue = tls_data
