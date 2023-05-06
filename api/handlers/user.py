from tornado.web import authenticated

from .auth import AuthHandler
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        def fernet(data):
            key = b'_hvalJR7aypIu1uOXUlyi55My3hX74DTixe1x_Y_HIc='
            f = Fernet(key)
            return f.decrypt(data).decode()

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['fullname'] = fernet(self.current_user['fullname'])
        self.response['address'] = fernet(self.current_user['address'])
        self.response['disability'] = fernet(self.current_user['disability'])
        self.response['displayName'] = self.current_user['display_name']

        self.write_json()



