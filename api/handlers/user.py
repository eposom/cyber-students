from tornado.web import authenticated

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        #self.response['full name'] = self.current_user['full name']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
