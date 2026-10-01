from scapy.all import *
#  entire class copied from https://github.com/secdev/scapy/blob/master/scapy/layers/eap.py#L439-L483
class EAPOL_KEY(Packet):
    name = "EAPOL_KEY"
    fields_desc = [
        ByteEnumField("key_descriptor_type", 1, {1: "RC4", 2: "RSN"}),
        # Key Information
        BitField("res2", 0, 2),
        BitField("smk_message", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("has_key_mic", 1, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
        BitField("res", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group/SMK", 1: "Pairwise"}),
        BitEnumField("key_descriptor_type_version", 0, 3, {
            1: "HMAC-MD5+ARC4",
            2: "HMAC-SHA1-128+AES-128",
            3: "AES-128-CMAC+AES-128",
        }),
        #
        LenField("len", None, "H"),
        LongField("key_replay_counter", 0),
        XStrFixedLenField("key_nonce", b"", 32),
        XStrFixedLenField("key_iv", b"", 16),
        XStrFixedLenField("key_rsc", b"", 8),
        XStrFixedLenField("key_id", b"", 8),
        XStrFixedLenField("key_mic", b"", 16),  # XXX size can be 24
        LenField("key_length", None, "H"),
        XStrLenField("key", b"",
                     length_from=lambda pkt: pkt.key_length)
    ]

    def extract_padding(self, s):
        return s[:self.len], s[self.len:]

    def hashret(self):
        return struct.pack("!B", self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, EAPOL_KEY) and \
                other.descriptor_type == self.descriptor_type:
            return 1
        return 0