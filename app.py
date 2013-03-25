import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.auth
import tornado.autoreload

import os
import logging
import pymongo
import json

from tornado.options import options, define

define("port", default=8000, type=int)
define("facebook_api_key")
define("facebook_secret")
define("cookie_secret")

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hi")

class Application(tornado.web.Application): 
    def __init__(self):
        dir_name = os.path.dirname(__file__)
        handlers = [
            (r'/', MainHandler)
        ]
        settings = {
            "template_path": os.path.join(dir_name, "templates"),
            "static_path": os.path.join(dir_name, "static"),
            "facebook_api_key": options.facebook_api_key,
            "facebook_secret": options.facebook_secret,
            "cookie_secret": options.cookie_secret,
            "xsrf_cookies": True
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
