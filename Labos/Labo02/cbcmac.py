from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Util import strxor
import base64


def cbcmac(message, key):
    """
    Computes the improved CBC-MAC of the message under the given key.
    @type message: bytes
    @param message: message to authenticate. This message *has* to be a 256-bit message to avoid extension attacks
    @type key: bytes
    @param key: An AES-256 key (see Crypto.Cipher.AES)
    @rtype: (bytes, bytes, bytes)
    @returns: a tuple consisting of the IV in base64, the message, and the tag in base64
    """

    if len(message) < 32:
        message = pad(message, 32, 'x923')
    elif len(message) > 32:
        raise Exception("Message must be 256bits or less")

    if len(key) < 32:
        key = pad(key, 32, 'x923')
    elif len(key) > 32:
        raise Exception("Key must be 256bits or less")

    cipher = AES.new(key, AES.MODE_CBC)
    tag = cipher.encrypt(pad(message, AES.block_size))
    iv = cipher.iv

    return iv, message, tag


def cbcmac_verify(message, key, iv, tag):
    """
    Verifies the given tag under the  improved CBC-MAC
    @type message: bytes
    @param message: the authenticated message.
    @type key: bytes
    @param key: An AES-256 key (see Crypto.Cipher.AES)
    @type iv: bytes
    @param iv: the IV in base64 under which the tag was computed.
    @type tag: bytes
    @param tag: the tag in base64
    @rtype: boolean
    @returns: true if the tag is valid. False otherwise.
    """

    if len(message) < 32:
        message = pad(message, 32, 'x923')
    elif len(message) > 32:
        raise Exception("Message must be 256bits or less")

    if len(key) < 32:
        key = pad(key, 32, 'x923')
    elif len(key) > 32:
        raise Exception("Key must be 256bits or less")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    tmp_tag = cipher.encrypt(pad(message, AES.block_size))

    return tag == tmp_tag


def cbc_mac_forge(iv, message, fake_message):

    iv_decoded = base64.b64decode(iv)
    tmp = strxor.strxor(iv_decoded, message[0:16])
    forged_iv = strxor.strxor(tmp, fake_message[0:16])
    forged_iv_encoded = base64.b64encode(forged_iv)

    return forged_iv_encoded
