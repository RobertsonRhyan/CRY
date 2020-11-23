from base64 import b64encode

from Labos.Labo02.cbcmac import *


def step1():
    print("Step 1 : CBC-MAC")
    print("--------------------------------------------\n")

    key = b"password"
    iv, message, tag = cbcmac(b"Envoyer 127'000 CHF vers siteABC", key)

    if cbcmac_verify(message, key, iv, tag):
        print("MAC's match")
    else:
        print("MAC's don't match")


def step1_2():
    print("\nStep 1.2")

    iv = b"+KegzOPbT6LKLafIVUT4xA=="
    message = b"Envoyer 127'000 CHF vers siteABC"
    tag = b"sxwvy0mGuUzO63L8wuyf5Q=="
    fake_message = b"Envoyer 999'000 CHF CHF vers siteABC"

    forged_iv = cbc_mac_forge(iv, message, fake_message)

    print("IV XOR M1               : ", strxor.strxor(base64.b64decode(iv), message[0:16]))
    print("Forged IV XOR Forged M1 : ", strxor.strxor(base64.b64decode(forged_iv), fake_message[0:16]))


def step2():
    print("Step2 : SPECK")
    print("--------------------------------------------\n")
    f = open("Robertson_Rhyan-speck.txt", "r")
    ct = f.read()

    cipher_text = base64.b64decode(ct)
    plain_text = b"\x00\x00\x00\x00"

    for i in range(100):
        ct1 = cipher_text[0 + i:4+i]
        ct2 = cipher_text[4+i:8+i]
        tmp = strxor.strxor(ct1, ct2)
        if(tmp == plain_text):
            print("found")



    print("Pause")


def step3():
    print("Step3 : Algorithme de chiffrement par blocs")
    print("--------------------------------------------\n")


def main():
    print("main")


if __name__ == "__main__":
    main()
    print("\n--------------------------------------------")
    step1()
    step1_2()
    print("\n--------------------------------------------")
    step2()
    print("\n--------------------------------------------")
    step3()
