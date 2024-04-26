from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify

'''
Función: encrypt_aes_ctr
Dado un mensaje y una clave (ambos en bytes), devuelve el cifrado AES-CTR.
'''
def encrypt_aes_ctr(key, message):
    iv = b'0000000000000000'
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return ct

'''
Función: decrypt_aes_ctr
Dado un cifrado y una clave (ambos en bytes), devuelve el mensaje original.
'''
def decrypt_aes_ctr(key, ciphertext):
    iv = b'0000000000000000'
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    m = decryptor.update(ciphertext) + decryptor.finalize()
    return m

'''
Función: xor
Realiza el XOR a nivel de bytes entre dos strings, str1 y str2.
Devuelve un valor de igual longitud que el string más pequeño proporcionado.
'''
def xor(str1, str2):
    return bytes(a ^ b for a, b in zip(str1, str2))

'''
Algunas funciones adicionales:

Función: hexlify
Proporciona la representación hexadecimal de un array de bytes.

Función: unhexlify
Proporciona la representación en bytes de un string hexadecimal.
'''
def main():

    # Si es necesario, se pueden utilizar las cabeceras conocidas para inferir información.
    # En este ejemplo, en la cabecera 3, el valor abc1234 representa un userID cuyo valor real no conocemos.
    ejemplo_cabecera_1 = b'<hello></hello>'
    ejemplo_cabecera_3 = b'<requestchannel>abc1234</requestchannel>'
    # Añadir aquí las demás cabeceras necesarias por el alumno...
    # ...

    # Aquí se proporcionan los cifrados interceptados en la comunicación.
    # cs significa enviado por el cliente y recibido por el servidor.
    # sc significa enviado por el servidor y recibido por el cliente.
    c1 = unhexlify('afd46ac79aa760a2333bb2e4e95803')
    c2 = unhexlify('afd46ac79aa760a2333bb2e4e95803')
    c3 = unhexlify('afce6ada83ad2dea7f3bb6e6eb5251f93229c1a5d3d394311c03971d7f301ec7cb8ca3fa072dd342')
    c4 = unhexlify('afcf6adf95a03ff07236bbb6b60201e80323d7ff8886cd63561dcc')
    c5 = unhexlify('afce6ada83ad2dea7736aeb6b60201e80223d2e98594d7665608cc')
    c6 = unhexlify('afcf6adf9dad27a02f66fabfb6030bfe417a8cef8593c8684a4f')
    c7 = unhexlify('afd16ad885a939fb2263e7b8b41a0bf7127792f9d1d4953b0345900a32305ad09885f3f5507e8b1a6685a64b3806177b84d3786edff56f1ab1f1f3a0a16233fd')
    c8 = unhexlify('afdd6cc893b82af37920a4e9e25203f7407692a0cf86c06e560186016f261ed2cf81fc')

    # A partir de aquí, operar con los cifrados para inferir información...
    # ...

# Ejecución del main
main()
