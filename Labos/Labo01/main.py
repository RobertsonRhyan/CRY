import unicodedata


def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    # Convert plain text to upper case
    text = text.upper()

    # Store the cipher text
    output = ""

    # Loop through every character in the text and shift *key* positions
    for i in range(len(text)):
        char = text[i]
        # If char is not in A-Z range, convert to unaccented char
        if ord(char) < 65 or ord(char) > 90:
            char = unicodedata.normalize('NFKD', char).encode('ASCII', 'ignore')

        # A - Z : ASCII = 65 - 90
        output += chr((ord(char) + key - 65) % 26 + 65)

    return output


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """

    # Reuse encrypt function, just reverse the key to shift back
    return caesar_encrypt(text, -key)


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.
    """
    # Contains occurrences of every lettre (a-z)
    freq_vector = [0] * 26

    # Convert all characters to lower case
    text = text.lower()

    # Loop through every character in text and count occurrences of every letter (a-z)
    for i in range(len(text)):
        char = text[i]
        if ord(char) >= 97 and ord(char) <= 122:
            freq_vector[ord(char) - 97] += 1

    # Sum total number of letters counted
    sum_letters = sum(freq_vector)

    # occurrences of a letter / total letters
    for i in range(len(freq_vector)):
        freq_vector[i] /= sum_letters

    return freq_vector


def caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    a number corresponding to the caesar key
    """
    # Chances of a letter
    stats = [0.07841540053061598, 0.00958838556217848, 0.030595746627351355, 0.04087027354168572, 0.1527957621095152,
             0.011080303168917446, 0.011543008747422572, 0.009057065848457765, 0.07269139825051549,
             0.0057750230473120855,
             0.0006553529581488962, 0.05655740012244984, 0.030790153343795524, 0.0738798302591855, 0.055087474225715874,
             0.029387082245476745, 0.01193006284351051, 0.07063561319924841, 0.08691475661334704, 0.07215128185279276,
             0.06516143674480468, 0.015051126327419615, 0.00041696282169473395, 0.004643769484655064,
             0.002656598568603579,
             0.0016687309551791357]

    tmp_sum = 100   # Best sum yet (100 is a random value that seeems high enough, might not be for a long text)
    tmp_key = 0     # Best key yet

    # Try key from 1-26 (a-z), more than 26 will just loop around
    for current_key in range(26):
        trial = caesar_decrypt(text, current_key)
        freq_vector = freq_analysis(trial)
        sum = 0
        for i in range(len(freq_vector)):
            sum += ((freq_vector[i] - stats[i]) ** 2) / stats[i]

        if sum < tmp_sum:
            tmp_sum = sum
            tmp_key = current_key

    return tmp_key


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    # TODO
    return ""


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    # TODO
    return ""


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    # TODO
    return 0


def vigenere_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    # TODO
    return ''


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    # TODO you can delete the next lines if needed
    vigenere_key = ""
    caesar_key = ''
    return (vigenere_key, caesar_key)


def main():
    print("Welcome to the Vigenere breaking tool\n")

    ################################################################################
    # 2 Chiffre de César Généralisé
    ################################################################################

    print("2. Chiffre de César Généralisé")
    plain_text = "LaCryptoCestRigolo"

    cipher_text = caesar_encrypt(plain_text, 9)

    print("Plain text       : ", plain_text)
    print("Cipher text      : ", cipher_text)
    print("Decrypted text   : ", caesar_decrypt(cipher_text, 9))

    ################################################################################
    # 2.1 Analyse de Fréquence
    ################################################################################

    print("\n2.1 Analyse de Fréquence\n")

    file1 = open("texte.txt", "r")

    keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z']

    freq_vector = freq_analysis(file1.read())
    file1.close()

    dictionary = dict(zip(keys, freq_vector))

    print(dictionary)

    ################################################################################
    # 2.2 Cesar Break
    ################################################################################

    print("\n2.5 Cesar Break\n")

    for i in range(27):
        tmp_cipher_text = caesar_encrypt(plain_text, i)
        print("Key = ", i)
        print("Plain text       : ", plain_text)
        print("Cipher text      : ", tmp_cipher_text)
        print("Best key found: ", caesar_break(tmp_cipher_text), "\n")


if __name__ == "__main__":
    main()
