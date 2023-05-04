from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)

            def excep(a):
                if not isinstance(a, str):
                    raise Exception()
            email = body['email'].lower().strip()
            excep(email)
            password = body['password']
            excep(password)
            full_name = body['fullname']
            excep(full_name)
            address = body['address']
            excep(address)
            disabilities = body['disabilities']
            excep(disabilities)
            dob = body['dateofbirth']
            excep(dob)
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            excep(display_name)
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        def send_erro(a):
            if not a:
                self.send_error(400, message=f'The {a} is invalid!')
            return
        send_erro(email)
        send_erro(full_name)
        send_erro(password)
        send_erro(display_name)

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        def hashing(a):
            '''This is the hashing function for password'''
            salt = os.urandom(16)
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            passphrase_bytes = bytes(a, "utf-8")
            hashed_passphrase = kdf.derive(passphrase_bytes)
            return hashed_passphrase.hex()

        def aes_ctr_encrypt(a):
            '''AES encryption function for PII'''
            key = "thebestsecretkeyintheentireworld"
            key_bytes = bytes(key, "utf-8")
            nonce_bytes = os.urandom(16)
            aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
            aes_ctr_encryptor = aes_ctr_cipher.encryptor()
            #aes_ctr_decryptor = aes_ctr_cipher.decryptor()
            plaintext_bytes = bytes(a, "utf-8")
            ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
            return ciphertext_bytes.hex()

        yield self.db.users.insert_one({
            'email': email,
            #'password': hashing(password),
            'password': aes_ctr_encrypt(password),
            'fullname': full_name,
            'address': aes_ctr_encrypt(address),
            'disabilities': aes_ctr_encrypt(disabilities),
            'dateofbirth': aes_ctr_encrypt(dob),
            'displayName': display_name
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['fullname'] = full_name
        self.response['address'] = address
        self.response['dateofbirth'] = dob
        self.response['disabilities'] = disabilities
        self.response['displayName'] = display_name

        self.write_json()
