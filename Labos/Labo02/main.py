from Labos.Labo02.cbcmac import *


def main():
    key = b"password"


    iv, message, tag = cbcmac(b"Envoyer 127'000 CHF vers siteABC", key)

    print(cbcmac_verify(message, key, iv, tag))




if __name__ == "__main__":
    main()