from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler
import os

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)

            def excep(a):
                '''String Exception FUnction'''
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
            disability = body['disability']
            excep(disability)
            dob = body['dateofbirth']
            excep(dob)
            phone_number = body['phoneNumber']
            excep(phone_number)
            display_name = body.get('displayName')

            if display_name is None:
                display_name = email
            excep(display_name)

        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        def send_erro(a):
            '''Error Code Exception Function'''
            if not a:
                self.send_error(400, message=f'The {a} is invalid!')
            return

        send_erro(email)
        send_erro(full_name)
        send_erro(password)
        send_erro(display_name)
        send_erro(phone_number)

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        def hashing(password):
            '''This is the hashing function for password'''
            salt = os.urandom(16)
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            passphrase_bytes = bytes(password, "utf-8")
            hashed_passphrase = kdf.derive(passphrase_bytes)
            return hashed_passphrase, salt

        def fernet(data):
            '''This is used to encrypt the PII'''
            key = b'_hvalJR7aypIu1uOXUlyi55My3hX74DTixe1x_Y_HIc='
            f = Fernet(key)
            return f.encrypt(bytes(data, "utf-8"))

        hashed_password = hashing(password)  #This generates a hashed value for password and also return the salt value used

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password[0],  #This returns the hashed password
            'fullname': fernet(full_name),
            'address': fernet(address),
            'disability': fernet(disability),
            'dateofbirth': fernet(dob),
            'phoneNumber': fernet(phone_number),
            'displayName': display_name,
            'salt': hashed_password[1],     #This returns the salt value

        })

        self.set_status(200)
        self.response['email'] = email
        self.response['fullname'] = full_name
        self.response['address'] = address
        self.response['dateofbirth'] = dob
        self.response['disability'] = disability
        self.response['phoneNumber'] = phone_number
        self.response['displayName'] = display_name


        self.write_json()