from scapy.layers.eap import EAP, EAPOL


def is_deauth(ev):
    payload = ev.split()[1]
    print(payload[0:2])
    return payload[0:2] == "c0"


def is_disass(ev):
    payload = ev.split()[1]
    return payload[0:2] == "a0"


def is_final_response(eapol):
    return eapol.code == 2 and eapol.type == 25


def is_id_response(eap):
    return eap.code == 2 and eap.type == 1


def is_challenge_response(eap):
    eap_payload = eap[1:]
    op_code = eap_payload[0]
    return eap[0] == 26 and op_code == 2

def is_challenge_response_v1(eap):
    eap_payload = eap.load
    op_code = eap_payload[0]
    return eap.code == 2 and eap.type == 26 and op_code == 2


def is_success_response(eap):
    eap_payload = eap[1:]
    op_code = eap_payload[0]
    return eap[0] == 26 and op_code == 3

def is_success_response_v1(eap):
    eap_payload = eap.load
    op_code = eap_payload[0]
    return eap.code == 2 and eap.type == 26 and op_code == 3


def is_tlv_result(eap):
    print('is result?' + str(eap.load[0:1]))
    return eap.load[0:2] == b''.fromhex("80 03")


def is_tlv_success(eap):
    return eap.load[5] == 1 and eap.load[0:2] == b''.fromhex("80 03")


def is_tlv_failure(eap):
    return eap.load[5] == 2 and eap.load[0:2] == b''.fromhex("80 03") and len(eap.load) == 6


def is_tlv_cryptobinding(eap):
    return eap.load[0:2] == b''.fromhex("00 0c") or eap.load[6:8] == b''.fromhex("00 0c")
