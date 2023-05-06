from tornado.web import authenticated

from .auth import AuthHandler
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = "thebestsecretkeyintheentireworld"
key_bytes = bytes(key, "utf-8")
# print("Key: " + key)

nonce_bytes = os.urandom(16)

aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                        mode=modes.CTR(nonce_bytes))
aes_ctr_encryptor = aes_ctr_cipher.encryptor()
aes_ctr_decryptor = aes_ctr_cipher.decryptor()

class UserHandler(AuthHandler):

    @authenticated
    # def aes_ctr_decrypt(a):
    #     '''AES encryption function for PII'''
    #     key = "thebestsecretkeyintheentireworld"
    #     key_bytes = bytes(key, "utf-8")
    #     nonce_bytes = os.urandom(16)
    #     aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
    #     ciphertext_bytes_restored = bytes.fromhex(a)
    #     # aes_ctr_encryptor = aes_ctr_cipher.encryptor()
    #     aes_ctr_decryptor = aes_ctr_cipher.decryptor()
    #     # plaintext_bytes = bytes(a, "utf-8")
    #     ciphertext_bytes = aes_ctr_decryptor.update(ciphertext_bytes_restored)
    #     return str(ciphertext_bytes, "utf-8")


    def get(self):
        def aes_decrypt(a):
            # key = "thebestsecretkeyintheentireworld"
            # key_bytes = bytes(key, "utf-8")
            # nonce_bytes = os.urandom(16)
            # aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
            aes_ctr_decryptor = aes_ctr_cipher.decryptor()
            cipher_bytes = bytes.fromhex(a)
            plaintext_bytes_2 = aes_ctr_decryptor.update(cipher_bytes)
            plaintext_2 = str(plaintext_bytes_2, "utf-8")
            return plaintext_2

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['fullname'] = self.current_user['fullname']
        self.response['address'] = aes_decrypt(self.current_user['address'])
        self.response['disability'] = aes_decrypt(self.current_user['disability'])
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()



# self.response['email'] = email
#         self.response['fullname'] = full_name
#         self.response['address'] = address
#         self.response['dateofbirth'] = dob
#         self.response['disability'] = disability
#         self.response['displayName'] = display_name