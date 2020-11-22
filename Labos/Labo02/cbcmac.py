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

    if len(key) < 32:
        key = pad(key, 32, 'x923')

    left_block = message[:16]
    right_block = message[16:]

    left_cipher = AES.new(key, AES.MODE_CBC)
    left_ct_bytes = left_cipher.encrypt(left_block)
    left_iv = left_cipher.iv #base64.b64encode(cipher.iv).decode('utf-8')
    left_ct = left_ct_bytes #base64.b64encode(left_ct_bytes).decode('utf-8')

    right_cipher = AES.new(key, AES.MODE_CBC)
    right_ct_bytes = right_cipher.encrypt(right_block)
    right_iv = right_cipher.iv
    right_ct = right_ct_bytes

    print("iv : , \ncipher : ")

    tag = left_ct + right_ct[0:]

    iv = left_iv + right_iv[0:]

    return (iv, message, tag)

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

    if len(key) < 32:
        key = pad(key, 32, 'x923')

    left_block = message[:16]
    right_block = message[16:]

    left_iv = iv[:16]
    right_iv = iv[16:]

    left_cipher = AES.new(key, AES.MODE_CBC, left_iv)
    left_ct_bytes = left_cipher.encrypt(left_block)
    left_ct = left_ct_bytes

    right_cipher = AES.new(key, AES.MODE_CBC, right_iv)
    right_ct_bytes = right_cipher.encrypt(right_block)
    right_ct = right_ct_bytes

    tmp_tag = left_ct + right_ct[0:]



    return tag == tmp_tag

