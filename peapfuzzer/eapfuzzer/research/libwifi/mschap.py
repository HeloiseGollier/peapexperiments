#!/usr/bin/env python3
import binascii, struct
from Crypto.Hash import MD4, SHA, HMAC
from Crypto.Cipher import DES


def des_encrypt(clear, key, offset):
    cNext = 0
    cWorking = 0
    hexKey = {}

    for x in range(0, 8):
        cWorking = 0xFF & key[x + offset]
        hexKey[x] = ((cWorking >> x) | cNext | 1) & 0xFF
        cWorking = 0xFF & key[x + offset]
        cNext = ((cWorking << (7 - x)))

    newKey = b""
    for x in range(0, len(hexKey)):
        newKey += struct.pack(">B", hexKey[x])

    des = DES.new(newKey, DES.MODE_ECB)
    return des.encrypt(clear)


def challenge_hash(peer_challenge, authenticator_challenge, username):
    challenge = SHA.new(peer_challenge + authenticator_challenge + username).digest()
    return challenge[0:8]


def nt_password_hash(password):
    unicode_pw = password.encode("utf-16-le")
    return MD4.new(unicode_pw).digest()


def hash_nt_password_hash(password_hash):
    md4 = MD4.new()
    md4.update(password_hash)
    return md4.digest()


def challenge_response(challenge, pwhash):
    # for some reason in python we need to pad an extra byte so that
    # the offset works out correctly when we call DesEncrypt
    pwhash += b'\x00' * (22 - len(pwhash))

    response = b""
    for x in range(0, 3):
        encrypted = des_encrypt(challenge, pwhash, x * 7)
        response += encrypted

    return response


def generate_nt_response_mschap2(authenticator_challenge, peer_challenge, username, password):
    challenge = challenge_hash(peer_challenge, authenticator_challenge, username)
    password_hash = nt_password_hash(password)
    return challenge_response(challenge, password_hash)


def generate_authenticator_response(password, nt_response, peer_challenge, authenticator_challenge, username):
    magic1 = b"\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74"
    magic2 = b"\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E"

    password_hash = nt_password_hash(password)
    password_hash_hash = hash_nt_password_hash(password_hash)

    sha_hash = SHA.new()
    sha_hash.update(password_hash_hash)
    sha_hash.update(nt_response)
    sha_hash.update(magic1)
    digest = sha_hash.digest()

    challenge = challenge_hash(peer_challenge, authenticator_challenge, username)

    sha_hash = SHA.new()
    sha_hash.update(digest)
    sha_hash.update(challenge)
    sha_hash.update(magic2)
    digest = sha_hash.digest()

    return digest


# wpa_supplicant code adapted for python
# get_master_key - GetMasterKey() - RFC 3079, Sect. 3.4
# @password_hash_hash: 16-octet PasswordHashHash (IN)
# @nt_response: 24-octet NTResponse (IN)
# @master_key: 16-octet MasterKey (OUT)
# Returns: 0 on success, -1 on failure
def get_master_key(password_hash_hash, nt_response):
    magic1 = b''.fromhex("54 68 69 73 20 69 73 20 74 68 65 20 4d 50 50 45 20 4d 61 73 74 65 72 20 4b 65 79")

    sha_hash = SHA.new()
    sha_hash.update(password_hash_hash)
    sha_hash.update(nt_response)
    sha_hash.update(magic1)
    digest = sha_hash.digest()[0:16]

    print("Master key: " + " ".join(f"{b:02x}" for b in digest))
    return digest


# wpa_supplicant code adapted for python
# get_asymetric_start_key - GetAsymetricStartKey() - RFC 3079, Sect. 3.4
# @master_key: 16-octet MasterKey (IN)
# @session_key: 8-to-16 octet SessionKey (OUT)
# @session_key_len: SessionKeyLength (Length of session_key) (IN)
# @is_send: IsSend (IN, BOOLEAN)
# @is_server: IsServer (IN, BOOLEAN)
# Returns: 0 on success, -1 on failure

def get_asymetric_start_key(master_key, is_send, is_server):
    magic2 = b''.fromhex("4f 6e 20 74 68 65 20 63 6c 69 65 6e 74 20 73 69 64 65 2c 20 74 68 69 73 20 69 73 20 74 68 65 "
                         "20 73 65 6e 64 20 6b 65 79 3b 20 6f 6e 20 74 68 65 20 73 65 72 76 65 72 20 73 69 64 65 2c 20 "
                         "69 74 20 69 73 20 74 68 65 20 72 65 63 65 69 76 65 20 6b 65 79 2e")

    magic3 = b''.fromhex("4f 6e 20 74 68 65 20 63 6c 69 65 6e 74 20 73 69 64 65 2c 20 74 68 69 73 20 69 73 20 74 68 65 "
                         "20 72 65 63 65 69 76 65 20 6b 65 79 3b 20 6f 6e 20 74 68 65 20 73 65 72 76 65 72 20 73 69 64"
                         " 65 2c 20 69 74 20 69 73 20 74 68 65 20 73 65 6e 64 20 6b 65 79 2e")

    shs_pad1 = b''.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                           "00 00 00 00 00 00 00 00 00 00")

    shs_pad2 = b''.fromhex("f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 "
                           "f2 f2 f2 f2 f2 f2 f2 f2 f2 f2")

    if is_send:
        if is_server:
            s = magic3
        else:
            s = magic2
    else:
        if is_server:
            s = magic2
        else:
            s = magic3

    sha_hash = SHA.new()
    sha_hash.update(master_key)
    sha_hash.update(shs_pad1)
    sha_hash.update(s)
    sha_hash.update(shs_pad2)
    digest = sha_hash.digest()
    return digest


def mschapv2_get_key(password, nt_response):
    password_hash = nt_password_hash(password)
    password_hash_hash = hash_nt_password_hash(password_hash)

    master_key = get_master_key(password_hash_hash, nt_response)
    key = (get_asymetric_start_key(master_key, False, True)[0:16]
           + get_asymetric_start_key(master_key, True, True)[0:16])
    print("EAP-MSCHAPV2: Derived key: " + " ".join(f"{b:02x}" for b in key))
    return key


# length should be 60
def peap_prfplus(temp_key, seed, length):
    counter = 1

    msg = seed + counter.to_bytes(1, 'big') + b''.fromhex("00 00")

    # /*
    #  * PRF+(K, S, LEN) = T1 | T2 | ... | Tn
    #  * T1 = HMAC-SHA1(K, S | 0x01 | 0x00 | 0x00)
    #  * T2 = HMAC-SHA1(K, T1 | S | 0x02 | 0x00 | 0x00)
    #  * ...
    #  * Tn = HMAC-SHA1(K, Tn-1 | S | n | 0x00 | 0x00)
    #  */
    t = HMAC.new(key=temp_key, digestmod=SHA)
    t.update(msg)
    t = t.digest()
    icmk = t
    pos = len(t)

    while pos < length:
        counter += 1
        temp = t + seed + counter.to_bytes(1, 'big') + b''.fromhex("00 00")

        t = HMAC.new(key=temp_key, digestmod=SHA)
        t.update(temp)
        t = t.digest()
        icmk += t
        pos += len(t)

    print("Derived ICMK: " + " ".join(f"{b:02x}" for b in icmk))
    return icmk


def derive_compound_mac(data, cmk):
    cm = HMAC.new(cmk, digestmod=SHA)
    cm.update(data)
    d = cm.digest()

    print("compound mac: " + " ".join(f"{b:02x}" for b in d))
    return d


def derive_csk(ipmk):
    return peap_prfplus(ipmk, "Session Key Generating Function".encode(), 128)


