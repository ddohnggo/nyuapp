import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.auth
import tornado.autoreload

import os
import logging
#import pymongo
import json

from tornado.options import options, define

define("port", default=8000, type=int)
define("facebook_api_key")
define("facebook_secret")
define("cookie_secret")
define("redirect_path")

class MainHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        access_token = self.get_secure_cookie('access_token')
        if not access_token: 
            print "don't have access token"
            self.redirect('/auth/login')
            return

        print self.settings['redirect_path']

        self.facebook_request(
            "/me/feed",
            access_token=access_token,
            callback=self.async_callback(self._on_facebook_user_feed))

    def _on_facebook_user_feed(self, response):
        name=self.get_secure_cookie('user_name')
        print "in user feed" + name
        print self.settings['redirect_path']
        self.render('home.html', feed=response['data'] if response else [], name=name)

class LoginHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        uid = self.get_secure_cookie('user_id')

        # check whether the FB token is passed in the query string
        if self.get_argument('code', None):
            self.get_authenticated_user(
                redirect_uri=self.settings['redirect_path'],
                client_id=self.settings['facebook_api_key'],
                client_secret=self.settings['facebook_secret'],
                code=self.get_argument('code'),
                callback=self.async_callback(self._on_facebook_login))
            return
        # check whether the person has a cookie
        elif self.get_secure_cookie('access_token'):
            self.redirect('/')
            return

        self.authorize_redirect(
            redirect_uri=self.settings['redirect_path'],
            client_id=self.settings['facebook_api_key'],
            extra_params={'scope': self.settings['scope']}
        )

    def _on_facebook_login(self, user):    
        if not user:
            self.clear_all_cookies()
            raise tornado.web.HTTPError(500, 'Facebook authentication failed')

        self.set_secure_cookie('user_id', str(user['id']))
        self.set_secure_cookie('user_name', str(user['name']))
        self.set_secure_cookie('access_token', str(user['access_token']))
        self.redirect('/')

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_all_cookies()
        self.render('logout.html')

class Application(tornado.web.Application): 
    def __init__(self):
        dir_name = os.path.dirname(__file__)
        handlers = [
            (r'/', MainHandler),
            (r'/auth/login', LoginHandler),
            (r'/auth/logout', LogoutHandler)
        ]
        settings = {
            "template_path": os.path.join(dir_name, "templates"),
            "static_path": os.path.join(dir_name, "static"),
            "facebook_api_key": options.facebook_api_key,
            "facebook_secret": options.facebook_secret,
            "cookie_secret": options.cookie_secret,
            "xsrf_cookies": True,
            "redirect_path": options.redirect_path
        }
        super(Application, self).__init__(handlers, **settings)

def main():
    tornado.options.parse_command_line() 
    dir_name = os.path.dirname(__file__)
    path = os.path.join(dir_name, "settings_dev.py")     
    tornado.options.parse_config_file(path)
    tornado.autoreload.add_reload_hook(lambda: "x")
    tornado.autoreload.start()
    httpserver = tornado.httpserver.HTTPServer(Application())
    httpserver.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
