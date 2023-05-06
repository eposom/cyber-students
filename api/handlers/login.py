from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
import os
import base64

from .base import BaseHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token


    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            # password = body['password']
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1,
            'salt' : 1

        }
            )

        def aes_ctr_encrypt(a):
            '''AES encryption function for PII'''
            key = "thebestsecretkeyintheentireworld"
            key_bytes = bytes(key, "utf-8")
            nonce_bytes = os.urandom(16)
            aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
            aes_ctr_encryptor = aes_ctr_cipher.encryptor()
            # aes_ctr_decryptor = aes_ctr_cipher.decryptor()
            plaintext_bytes = bytes(a, "utf-8")
            ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
            return ciphertext_bytes.hex()

        def hashing(a):
            '''This is the hashing function for password'''
            salt = user['salt']
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            passphrase_bytes = bytes(a, "utf-8")
            hashed_passphrase = kdf.derive(passphrase_bytes)
            return hashed_passphrase.hex()

        # a = user['password']
        # old_password = aes_ctr_encrypt(password)
        # print(old_password)
        data_string = user['salt']
        base64_string = data_string.split(", ")[1][1:-1]
        binary_data = base64.b64decode(base64_string)
        old_password = hashing(binary_data)

        if user is None:
            self.send_error(403, message='invalid user!')
            return

        if user['password'] != old_password:
            print(user['salt'])
            self.send_error(403, message=binary_data)
            return
        print(old_password)
        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
