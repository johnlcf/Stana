#!/usr/bin/env python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


import logging
import re
from StatBase import StatBase

class streamList(list):
    def __init__(self,*args,**kwargs):
        self._metadata = {}
        list.__init__(self, args, **kwargs)

class StatStreams(StatBase):
    """ Stat and follow streams in strace"""
    SYSCALLS = "open socket connect read write close".split()
    RE_PAT = dict(
        ip_address=re.compile('.*[^0-9]((?:[0-9]{1,3}\.){3}[0-9]{1,3})[^0-9].*'))

    def __init__(self):
        #key = OF number
        self._open_streams = {}
        #store the finished streams
        self._closed_streams = []
        
        #define stdin, stdout and stderr
        self._open_streams[0] = streamList('STDIN')
        self._open_streams[0]._metadata['type'] = 'STDIN'
        self._open_streams[1] = streamList('STDOUT')
        self._open_streams[1]._metadata['type'] = 'STDOUT'
        self._open_streams[2] = streamList('STDERR')
        self._open_streams[2]._metadata['type'] = 'STDERR'

    def getSyscallHooks(self):
        return_dict = {}
        for syscall in StatStreams.SYSCALLS:
            return_dict[syscall] = self.statStreams
        return return_dict

    def isOperational(self, straceOptions):
        return True

    def openStream(self, syscall, retcode, args):
        if retcode == -1:
            #file not found, do nothing
            return

        stream_nr = retcode
        file_name = args[0]

        if stream_nr in self._open_streams:
            #the filehandle should have been closed! we missed it
            logging.warn("Missed closing of stream %s", stream_nr)
            self.close_stream(stream_nr)

        st_type = dict(open="file",socket="socket")[syscall]
        sl = streamList("%s(%s) %s" % (st_type , stream_nr, ', '.join(args)))
        sl._metadata['type'] = st_type
        sl._metadata['opening_args'] = args
        self._open_streams[stream_nr] = sl

    def socketConnect(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            print args[1][0]
            print args[1]
            if args[1][0].startswith('sa_family=AF_INET'):
                stream.append('Connected to %s' % StatStreams.RE_PAT['ip_address'].match(args[1][2]).group(1))
        else:
            logging.error("Missed openning %s", stream_nr)

        
    def readStream(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            stream.append('<<' + ', '.join(args[1:]))
        else:
            logging.error("Missed openning %s", stream_nr)
            

    def writeStream(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            stream.append('>>' + ', '.join(args[1:]))
        else:
            logging.error("Missed openning %s", stream_nr)

    def closeStream(self, syscall, retcode, args):
        stream_nr = int(args[0])
        self._closed_streams.append('\n'.join(self._open_streams[stream_nr]) + \
                            ('\nclosed(%s)\n' % stream_nr))
        del self._open_streams[stream_nr]

    def statStreams(self, result):
        logging.debug(result)
        syscall, retcode, args = result["syscall"], int(result["return"]), result["args"]

        if syscall in StatStreams.SYSCALLS:
            dict(open=self.openStream,
                socket=self.openStream,
                connect=self.socketConnect,
                read=self.readStream,
                write=self.writeStream,
                close=self.closeStream)[syscall](syscall, retcode, args)
                
            
    def printOutput(self):
        #close all open streams
        for stream in self._open_streams.keys():
            self.closeStream(None, None, [stream])

        print "====== File Streams ======"
        print '\n'.join(self._closed_streams)


