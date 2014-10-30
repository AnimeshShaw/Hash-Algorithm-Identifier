#!/usr/bin/env python
'''
Yay, web services

@author: moloch
'''

import tornado.ioloop
import tornado.web
import tornado.log

from tornado.options import define, options
from HashIdentifier import identify_hashes


class MainHandler(tornado.web.RequestHandler):

    ''' Creates a simple JSON API '''

    def get(self, *args):
        results = identify_hashes(args[0])
        self.write({'results': results})


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
