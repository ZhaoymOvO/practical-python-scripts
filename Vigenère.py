import base64
import binascii


def unicode_vigenere_encrypt(plaintext: str, key: str, use_base64: bool = True):
    """
    Vigenère Cipher encrypt
    :param plaintext: the text that you want to encrypt
    :param key: encrypt key
    :param use_base64: use base64 encode the output or not
    :return: encrypted text
    """
    encrypted_text_raw = ""
    key_index = 0

    for char in plaintext:
        p_code = ord(char)
        k_code = ord(key[key_index % len(key)])
        encrypted_code = p_code + k_code
        encrypted_text_raw += chr(encrypted_code)

        key_index += 1

    if use_base64:
        raw_bytes = encrypted_text_raw.encode('utf-8')
        base64_bytes = base64.b64encode(raw_bytes)
        return base64_bytes.decode('utf-8')
    else:
        return encrypted_text_raw


def unicode_vigenere_decrypt(ciphertext, key, use_base64=True):
    """
    Vigenère Cipher decrypt
    :param ciphertext: encrypted text
    :param key: encrypt key
    :param use_base64: use base64 encode the output or not
    :return: decrypted text
    :raises SyntaxError: use_base64 is True and ciphertext is not valid base64 encoded text
    """
    raw_ciphertext = ""

    if use_base64:
        try:
            base64_bytes = ciphertext.encode('utf-8')
            raw_bytes = base64.b64decode(base64_bytes)
            raw_ciphertext = raw_bytes.decode('utf-8')
        except binascii.Error:
            raise SyntaxError("ciphertext is not valid base64 encoded text")
    else:
        raw_ciphertext = ciphertext

    decrypted_text = ""
    key_index = 0

    for char in raw_ciphertext:
        c_code = ord(char)
        k_code = ord(key[key_index % len(key)])
        decrypted_code = c_code - k_code
        decrypted_text += chr(decrypted_code)

        key_index += 1

    return decrypted_text


if __name__ == '__main__':
    help_text = """:(exit|quit|q)\t\t\t-> quit
:(e|enc|encrypt)\t\t-> encrypt mode
:(d|dec|decrypt)\t\t-> decrypt mode
:(setkey|keyset)\t\t-> set encrypt/decrypt key
:(key|showkey)\t\t\t-> print current key"""
    key = ""
    mode = 0
    while 1:
        user_input = input(f"{['input :h for help', 'encrypt', 'decrypt'][mode]}, key status: {bool(key)}> ").strip()
        if user_input.startswith(':'):
            user_input = user_input.lower()[1:].strip()
            if user_input in ['setkey', 'keyset']:
                key = input('set new key: ')
            elif user_input in ['key', 'showkey']:
                print(key)
            elif user_input in ['exit', 'quit', 'q']:
                break
            elif user_input in ['e', 'enc', 'encrypt']:
                mode = 1
            elif user_input in ['d', 'dec', 'decrypt']:
                mode = 2
            elif user_input in ['h', 'help']:
                print(help_text)
        elif mode == 0 or key == "":
            if mode == 0:
                print('please set mode first')
            if key == "":
                print('please set key first')
        elif mode == 1:
            print(unicode_vigenere_encrypt(user_input, key))
        elif mode == 2:
            try:
                print(unicode_vigenere_decrypt(user_input, key))
            except SyntaxError:
                print("please input valid base64 encoded text")
