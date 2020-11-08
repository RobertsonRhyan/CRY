import unicodedata
from math import ceil


def normalize_text(text):
    """
    Parameters
    ----------
    text: the text to normalize

    Returns
    -------
    normalized <text> in upper or lower case depending on <case>
    """
    output = ""
    for i in text:
        char = i
        char_num = ord(i)

        if char_num < 65:
            continue

        if 90 < char_num < 97:
            continue

        # If char is not in A-Z range, convert to unaccented char
        if char_num < 65 or char_num > 90:
            char = str(unicodedata.normalize('NFKD', i).encode('ASCII', 'ignore'), 'ASCII')

        output += char

    return output.upper()


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
    # Normalize text
    text = normalize_text(text)

    # Store the cipher text
    output = ""

    # Loop through every character in the text and shift *key* positions
    # for i in range(len(text)):
    #    char = text[i]
    #    # A - Z : ASCII = 65 - 90
    #    output += chr((ord(char) + key - 65) % 26 + 65)

    for i in text:
        # A - Z : ASCII = 65 - 90
        output += chr((ord(i) + key - 65) % 26 + 65)

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


def freq_letters(text):
    # Contains occurrences of every lettre (a-z)
    freq_vector = [0] * 26

    # Normalize text
    text = normalize_text(text)

    # Loop through every character in text and count occurrences of every letter (A-Z)
    for i in text:
        if 65 <= ord(i) <= 90:
            freq_vector[ord(i) - 65] += 1

    return freq_vector


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

    # Normalize text
    text = normalize_text(text)

    # Loop through every character in text and count occurrences of every letter (A-Z)
    for i in text:
        if 65 <= ord(i) <= 90:
            freq_vector[ord(i) - 65] += 1

    # Sum total number of letters counted
    sum_letters = sum(freq_vector)

    # Occurrences of a letter / total letters
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
    # Letter frequencies for French
    stats = [0.08152736532371435, 0.009264280165431146, 0.03018370472614278, 0.039488781721660225, 0.1725705912650587,
             0.010705768161813827, 0.01115283342484289, 0.008750920053511841, 0.07133920694362048, 0.00557981644826197,
             0.0006332008002978168, 0.05464565403268166, 0.029749388472515684, 0.07138255357558718,
             0.053824617827194825, 0.028393743806106264, 0.01152680436730066, 0.06824799713062295, 0.08397687499681275,
             0.06971243334392918, 0.06373144806648523, 0.014542370057846506, 0.00040286869710223517,
             0.004486801375533121, 0.0025676504935566507, 0.001612324722369072]

    tmp_sum = 100  # Best sum yet (100 is a random value that seems high enough, might not be for a long text)
    tmp_key = 0  # Best key yet

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
    # Normalize text
    text = normalize_text(text)

    keys = normalize_text(key)
    key_length = len(keys)
    output = ""

    for i in range(len(text)):
        current_key = ord(keys[i % key_length]) - 65
        char = caesar_encrypt(text[i], current_key)
        output += char

    return output


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

    # Normalize text
    text = normalize_text(text)

    keys = normalize_text(key)
    key_length = len(keys)
    output = ""

    for i in range(len(text)):
        current_key = ord(keys[i % key_length]) - 65
        char = caesar_decrypt(text[i], current_key)
        output += char

    return output


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """

    text = normalize_text(text)
    N = len(text)  # Length of text
    freq_vector = freq_letters(text)  # Get frequencies of lettres

    sum_freq = 0

    for i in range(26):
        sum_freq += freq_vector[i] * (freq_vector[i] - 1)

    ic = sum_freq / (N * (N - 1))

    return ic


def find_key_length(text):
    """
    Doesn't work well with short text as the last sequence is to short
    Parameters
    ----------
    text: the ciphertext to get key length from

    Returns
    -------
    the best keyword length found
    """

    text = normalize_text(text)
    ################################################################################
    # Find key length
    ################################################################################

    max_key_length_test = 20
    text_len = len(text)
    best_ic = 0
    best_key_length = 0

    for l in range(1, max_key_length_test):
        seq = ""
        for i in range(text_len):
            idx = i * l
            if idx > text_len - 1:
                break
            seq += text[idx]

        ic = coincidence_index(seq)
        print(l, " : ", ic)
        if ic > best_ic:
            best_ic = ic
            best_key_length = l

    return best_key_length


def vigenere_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """

    text = normalize_text(text)

    # Best key length found with Index of Coincidence
    key_length = find_key_length(text)
    text_length = len(text)

    key = ""

    # Break <key_length> Caesar ciphers.
    # First cipher is constructed using every <key_length>th letter starting with the first
    # Same for the second cipher but starting at the second letter, etc...
    for start in range(key_length):
        seq = ""
        for i in range(text_length):
            idx = start + (i * key_length)
            if idx > text_length - 1:
                break
            seq += text[idx]

        # With Chi-squared, find the best key for the current sequence
        key += chr(65 + caesar_break(seq))

    return key


def extend_vigenere_key(vigenere_key, caesar_key, text_len):
    key_len = len(vigenere_key)

    if text_len > key_len:
        mul = ceil(text_len / key_len)

    new_vigenere_key = vigenere_key

    for i in range(mul):
        vigenere_key = caesar_encrypt(vigenere_key, caesar_key)
        new_vigenere_key += vigenere_key

    return new_vigenere_key[0:text_len]


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
    text = normalize_text(text)
    vigenere_key = normalize_text(vigenere_key)

    new_vigenere_key = extend_vigenere_key(vigenere_key, caesar_key, len(text))

    return vigenere_encrypt(text, new_vigenere_key)


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
    text = normalize_text(text)
    vigenere_key = normalize_text(vigenere_key)

    new_vigenere_key = extend_vigenere_key(vigenere_key, caesar_key, len(text))

    return vigenere_decrypt(text, new_vigenere_key)


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
    vigenere_key = ""
    caesar_key = ''

    text = normalize_text(text)

    # Best key length found with Index of Coincidence
    key_length = find_key_length(text)
    text_length = len(text)

    return vigenere_break(text)


def main():
    test_text = "To be, or not to be, that is the question Whether 'tis Nobler in the mind to suffer " \
                "The Slings and Arrows of outrageous Fortune, Or to take Arms against a Sea of troubles, " \
                "And by opposing end them? William Shakespeare - Hamlet"
    test_key = "ABCCDEEFGGHIIJKKLMMNOOPQQRSSTUUVWWXYYZAABCCDEEFGGHIIJKKLMMNOOPQQRSSTUUVWWXYYZAABCCDE" \
               "EFGGHIIJKKLMMNOOPQQRSSTUUVWWXYYZAABCCDEEFGGHIIJKKLMMNOOPQQRSSTUUVWWXYYZAABCCDEEFGGHIIJKKLMMNO"

    print("\nWelcome to the Vigenere breaking tool\n")

    ####################################################################################################################
    # 2. Chiffre de César Généralisé
    ####################################################################################################################

    print("2. Chiffre de César Généralisé\n")
    plain_text = "LaCryptoCestRigolo"

    cipher_text = caesar_encrypt(plain_text, 9)

    print("   Plain text       : ", plain_text)
    print("   Cipher text      : ", cipher_text)
    print("   Decrypted text   : ", caesar_decrypt(cipher_text, 9))

    ####################################################################################################################
    # 2.1 Analyse de Fréquence
    ####################################################################################################################

    print("\n2.1 Analyse de Fréquence\n")

    file1 = open("texte.txt", "r")
    text_french = file1.read()
    file1.close()

    keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z']

    freq_vector = freq_analysis(text_french)

    dictionary = dict(zip(keys, freq_vector))

    print("  ", dictionary)

    ####################################################################################################################
    # 2.5 Cesar Break
    ####################################################################################################################

    print("\n2.5 Cesar Break\n")
    print("   Plain text       : ", plain_text)

    all_keys_match = True

    # Try for each key between 0 and 25
    for i in range(26):
        print("   Key              : ", i)

        tmp_cipher_text = caesar_encrypt(plain_text, i)
        print("   Cipher text      : ", tmp_cipher_text)

        key_found = caesar_break(tmp_cipher_text)
        print("   Best key found   : ", key_found)
        print("   Plain text       : ", caesar_decrypt(tmp_cipher_text, key_found), "\n")

        if i != key_found:
            all_keys_match = False

    if all_keys_match:
        print("   All keys found !\n")

    ####################################################################################################################
    # 3. Chiffre de Vigenère
    ####################################################################################################################

    print("3. Chiffre de Vigenère\n")

    plain_text_vigenere_1 = "Vigenère"
    plain_text_vigenere_2 = "La crypto c'est rigolo"

    keys_vigenere_1 = "ABC"
    keys_vigenere_2 = "xyz"

    cipher_text_vigenere_1 = vigenere_encrypt(plain_text_vigenere_1, keys_vigenere_1)
    cipher_text_vigenere_2 = vigenere_encrypt(plain_text_vigenere_2, keys_vigenere_2)

    print("   From plain text to cipher :")
    print("  ", plain_text_vigenere_1, " : ", cipher_text_vigenere_1)
    print("  ", plain_text_vigenere_2, " : ", cipher_text_vigenere_2)

    print("\n   From cipher text to plain : ")
    print("  ", cipher_text_vigenere_1, " : ", vigenere_decrypt(cipher_text_vigenere_1, keys_vigenere_1))
    print("  ", cipher_text_vigenere_2, " : ", vigenere_decrypt(cipher_text_vigenere_2, keys_vigenere_2))

    ####################################################################################################################
    # 3.1 Indice de Coïncidence
    ####################################################################################################################

    # The Index of Coincidence (I.C.) is a statistical technique that gives an indication of how English-like
    # a piece of text is.

    print("\n3.1 Indice de Coïncidence\n")

    print("   Texte francais : ", coincidence_index(text_french))

    cipher_test_text = vigenere_encrypt(test_text, "ABC")

    print("   Plain text   : ", coincidence_index(test_text))
    print("   Cipher text  : ", coincidence_index(cipher_test_text))

    ####################################################################################################################
    # 3.2 Cryptanalyse du Chiffre de Vigenère
    ####################################################################################################################

    print("\n3.2 Vigenere break\n")
    file2 = open("vigenere.txt", "r")
    text_vigenere = file2.read()
    file2.close()
    keys_vigenere_break = vigenere_break(text_vigenere)
    print("   Key : ", keys_vigenere_break)
    print("   Plain text : ", vigenere_decrypt(text_vigenere, keys_vigenere_break))

    ####################################################################################################################
    # 4.13 Vigenere Caesar encrypt
    ####################################################################################################################
    print("\n4.13 Vigenere amelioree\n")

    test_text_cipherd = vigenere_caesar_encrypt(test_text, "MAISON", 2)

    print("   Plain text       : ", normalize_text(test_text))
    print("   Cipher text      : ", test_text_cipherd)
    print("   Deciphered text  : ", vigenere_caesar_decrypt(test_text_cipherd, "MAISON", 2))

    ####################################################################################################################
    # 4.14 Vigenere Caesar break
    ####################################################################################################################
    print("\n4.14 Vigenere amelioree break\n")
    file3 = open("vigenereAmeliore.txt", "r")
    text_vigenere_amelioree = file3.read()
    file3.close()

    test = "NOUSNESOMMESPASDESETRANGERSDELAMOURTUCONNAISLESREGLESTOUTCOMMEMOIUNENGAGEMENTCOMPLETESTCEAQUOIJEPENSETUN" \
           "OBTIENDRAISJAMAISCECIDUNAUTREGARSJEVEUXJUSTETEDIRECEQUEJERESSENSJEDOISTEFAIRECOMPRENDREJENETABANDONNERAI" \
           "JAMAISJENETELAISSERAIJAMAISTOMBERJENEVAISPASTETOURNERAUTOURPUISTABANDONNERJENETEFERAIJAMAISPLEURERJENETE" \
           "DIRAIJAMAISAUREVOIRJENETEMENTIRAIJAMAISNITEFERAIDUMALNOUSNOUSCONNAISSONSDEPUISSILONGTEMPSTONCOEURASOUFFE" \
           "RTMAISTUESTROPTIMIDEPOURLEDIREINTERIEUREMENTNOUSSAVONSTOUSLESDEUXCEQUISESTPASSENOUSCONNAISSONSLEJEUETNOU" \
           "SALLONSLEJOUERETSITUMEDEMANDESCOMMENTJEMESENSNEMEDISPASQUETUESTROPAVEUGLEPOURVOIRJENETABANDONNERAIJAMAIS" \
           "JENETELAISSERAIJAMAISTOMBERJENEVAISPASTETOURNERAUTOURPUISTABANDONNERJENETEFERAIJAMAISPLEURERJENETEDIRAIJ" \
           "AMAISAUREVOIRJENETEMENTIRAIJAMAISNITEFERAIDUMALTABANDONNERTABANDONNERJENEVAISJAMAISJENEVAISJAMAISTABANDO" \
           "NNERJENEVAISJAMAISJENEVAISJAMAISTABANDONNERNOUSNOUSCONNAISSONSDEPUISSILONGTEMPSTONCOEURASOUFFERTMAISTUES" \
           "TROPTIMIDEPOURLEDIREINTERIEUREMENTNOUSSAVONSTOUSLESDEUXCEQUISESTPASSENOUSCONNAISSONSLEJEUETNOUSALLONSLEJ" \
           "OUERETSITUMEDEMANDESCOMMENTJEMESENSNEMEDISPASQUETUESTROPAVEUGLEPOURVOIRJENETABANDONNERAIJAMAISJENETELAIS" \
           "SERAIJAMAISTOMBERJENEVAISPASTETOURNERAUTOURPUISTABANDONNERJENETEFERAIJAMAISPLEURERJENETEDIRAIJAMAISAUREV" \
           "OIRJENETEMENTIRAIJAMAISNITEFERAIDUMAL"
    cipher_test = vigenere_caesar_encrypt(test, "RICKROLLED", 2)
    print(cipher_test)


if __name__ == "__main__":
    main()
