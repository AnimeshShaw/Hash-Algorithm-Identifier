#!/usr/bin/env python
'''
Yay, web services

@author: moloch
'''

import json
import tornado.ioloop
import tornado.web
import tornado.log

from tornado.gen import coroutine, Return
from tornado.options import define, options
from HashIdentifier import identify_hashes


class MainHandler(tornado.web.RequestHandler):

    ''' Creates a simple JSON API '''

    def initialize(self):
        self.set_header("Server", "HashIdentifier")
        self.set_header("X-Content-Type-Options", "nosniff")

    @coroutine
    def identify_hashes(self, hsh):
        ''' Just a small async wrapper function '''
        raise Return(identify_hashes(hsh))

    @coroutine
    def get(self, *args):
        ''' GET idnetifies a single hash '''
        results = yield self.identify_hashes(args[0])
        self.write({args[0]: results})

    @coroutine
    def post(self, *args):
        ''' POST can accept multiple hashes '''
        response = {}
        try:
            hashes = json.loads(self.request.body)['hashes']
            for hsh in set(hashes):
                response[hsh] = yield self.identify_hashes(hsh)
        except ValueError:
            response = {'error': 'could not parse request'}
        self.write(response)


application = tornado.web.Application([
    (r"/(.*)", MainHandler),
])

define("port",
       default="8888",
       type=int,
       help="the listen port for the web server"
       )

if __name__ == "__main__":
    tornado.options.parse_command_line()
    application.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
