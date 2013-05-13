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

from urlparse import urlparse
from tornado.options import options, define

define("port", default=8000, type=int)
define("facebook_api_key")
define("facebook_secret")
define("cookie_secret")
define("redirect_path")
define("scope")
MONGO_URL = os.environ.get('MONGOHQ_URL')

def getattrib(self, val):
    value = self.get_secure_cookie(val)
    return value

class TripListHandler(tornado.web.RequestHandler):
    def get(self):
        trips = dict()
        uid = self.get_secure_cookie('user_id') 
        trip_db = self.application.db.trips
        trips = trip_db.find({'uid': uid})
        trips_list = []
        for i in trips:
            trips_list.append(i['tripName'])
        trips_list.sort()
        self.render('version2/tripList3.html', name=getattrib(self, 'user_name'), pic=getattrib(self, 'photo'), trips=trips_list)

class NewTripHandler(tornado.web.RequestHandler):
    def get(self, tripName=None):
        trip = dict()
        if tripName:
            trip_db = self.application.db.trips
            trip = trip_db.find_one({'tripName': tripName})
        self.render('version2/newTrip2.html', name=getattrib(self, 'user_name'), pic=getattrib(self, 'photo'), trip=trip)
    
    def post(self, tripName=None):
        trip_fields = ['uid', 'tripName', 'airline', 'confirmation', 'departwhere', 'departday', 'departtime',
                       'arrivewhere', 'arriveday', 'arrivetime', 'flight', 'terminal', 'gate', 'seat',
                       'hotel', 'zipcode', 'room', 'inday', 'intime', 'outday', 'outtime', 'todo1', 'todo2', 'todo3']

        trip = dict()
        for key in trip_fields:
            trip[key] = self.get_argument(key, None)
        trip['uid'] = self.get_secure_cookie('user_id') 
        trip_db = self.application.db.trips
        print trip
        trip_db.save(trip)
        self.redirect('/triplist')

class ListHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('list.html', name=getattrib(self, 'user_name'), pic=getattrib(self, 'photo'))

class StayHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('stay.html', name=getattrib(self, 'user_name'), pic=getattrib(self, 'photo'))

class FlightHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('flight.html', name=getattrib(self, 'user_name'), pic=getattrib(self, 'photo'))

class MainHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        access_token = self.get_secure_cookie('access_token')
        print "access token is %s" % access_token
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
        name = self.get_secure_cookie('user_name')
        pic = self.get_secure_cookie('photo')
        trips = dict()
        uid = self.get_secure_cookie('user_id')
        trip_db = self.application.db.trips
        trip_cnt = trip_db.find({'uid': uid}).count()
        print "in user feed " + name
        print self.settings['redirect_path']
        print "picture "
        self.render('version2/home.html', feed=response['data'] if response else [], name=name, pic=pic, trip_cnt=trip_cnt)

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

        print user
        self.set_secure_cookie('user_id', str(user['id']))
        self.set_secure_cookie('user_name', str(user['name']))
        self.set_secure_cookie('access_token', str(user['access_token']))
        self.set_secure_cookie('fbid', str(user['id']))
        self.set_secure_cookie('locale', str(user['locale']))
        self.set_secure_cookie('photo', str(user['picture']['data']['url']))
        self.set_secure_cookie('session_expoires', str(user['session_expires']))

        # save to db
        user_db = self.application.db.users 
        user = {
            "user_id": str(user['id']),
            "user_name": str(user['name']),
            "access_token": str(user['access_token']),
            "fbid": str(user['locale']),
            "access_token": str(user['access_token']),
            "photo": str(user['picture']['data']['url'])
            }
        user_db.save(user)
        self.redirect('/')

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_all_cookies()
        self.render('logout.html')

class Application(tornado.web.Application): 
    def __init__(self):
        dir_name = os.path.dirname(__file__)
        if MONGO_URL:
            # get a connection
            conn = pymongo.Connection(MONGO_URL)
            
            # get the db
            self.db = conn[urlparse(MONGO_URL).path[1:]]
        else:
            # not an app with mongohq, localhost instead
            conn = pymongo.Connection("localhost", 27017)
            self.db = conn["example"]

        handlers = [
            (r'/', MainHandler),
            (r'/auth/login', LoginHandler),
            (r'/auth/logout', LogoutHandler),
            (r'/flight', FlightHandler),
            (r'/stay', StayHandler),
            (r'/list', ListHandler),
            (r'/triplist', TripListHandler),
            (r'/edit/([0-9A-Za-z\-\s]+)', NewTripHandler),
            (r'/trip', NewTripHandler)
        ]
        settings = {
            "template_path": os.path.join(dir_name, "templates"),
            "static_path": os.path.join(dir_name, "static"),
            "facebook_api_key": options.facebook_api_key,
            "facebook_secret": options.facebook_secret,
            "cookie_secret": options.cookie_secret,
            "xsrf_cookies": False,
            "redirect_path": options.redirect_path,
            "scope": options.scope
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
