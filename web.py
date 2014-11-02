#!/usr/bin/env python
'''
@about: Web service wrapper for hash identifcation.
@author: moloch

Usage: ./web.py or see --help for more options

--------------------------------------------------------------------------
JavaScript Simple Example
--------------------------------------------------------------------------
var hash = "3da541559918a808c2402bba5012f6c60b27661c";

cors_request = new XMLHttpRequest();
cors_request.onreadystatechange = function() {
    if (cors_request.readyState == 4) {
        console.log(cors_request.responseText);
    }
}
cors_request.open("GET", "http://hashid.badwith.computer/" + hash);
cors_request.send();


--------------------------------------------------------------------------
Python Simple Example
--------------------------------------------------------------------------
import requests

hsh = "3da541559918a808c2402bba5012f6c60b27661c"
resp = requests.get("http://hashid.badwith.computer/%s" % hsh)
print resp.text


--------------------------------------------------------------------------
Python Multiple Hash Identification Example
--------------------------------------------------------------------------
import json
import requests

hashes = {'hashes': [
                     "3da541559918a808c2402bba5012f6c60b27661c",
                     "912ec803b2ce49e4a541068d495ab570"
                    ]}

resp = requests.post("http://hashid.badwith.computer/", data=json.dumps(hashes))
print resp.text
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
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Methods", "GET, POST")

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
