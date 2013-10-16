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
    """A list object extended to a _metadata dictionary"""
    def __init__(self,*args,**kwargs):
        self._metadata = {}
        list.__init__(self, args, **kwargs)

class StatStreams(StatBase):
    """ Stat and follow streams in strace"""
    #Syscalls this object will be registered with
    SYSCALLS = "open socket connect read write close".split()

    #some regexp for extracting information out of the strace log lines
    RE_PAT = dict(
        ip_address=re.compile('.*[^0-9]((?:[0-9]{1,3}\.){3}[0-9]{1,3})[^0-9].*'),
        #set of printable unicode characters 
        #(no control charaters and \t \n \r (:= 9,10,13)
        no_str=re.compile('[%s]' % re.escape(''.join(map(unichr, range(0,8) + [11, 12] + range (14,32) + range(127,256))))),
        no_ascii=re.compile('[^%s]' % re.escape(''.join(map(chr, range(33,126))))))

    #markers for displaying the output
    OUT_MARKER = '>>>>'
    IN_MARKER = '<<<<'

    def __init__(self):
        #key = OF number
        self._open_streams = {}
        #store the finished streams
        self._closed_streams = []

        #some defaults
        self.show_text = True       #display streams contents
        self.show_binary = True     #display binary streams
        self.show_online = False    #display streams as soon as they are closed
        
        #define stdin, stdout and stderr
        names = ['STDIN', 'STDOUT', 'STDERR']
        for num in range(3):
            self._open_streams[num] = streamList(names[num])
            self._open_streams[num]._metadata = dict(type=names[num],  out=0)
            self._open_streams[num]._metadata['in'] = 0


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
        sl._metadata['in'] = 0
        sl._metadata['out'] = 0
        self._open_streams[stream_nr] = sl

    def socketConnect(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            if args[1][0] == 'sa_family=AF_INET':
                stream.append('Connected to %s' % StatStreams.RE_PAT['ip_address'].match(args[1][2]).group(1))
            elif args[1][0] == 'sa_family=AF_INET6':
                stream.append('Connected to %s' % args[1][3])
        else:
            logging.error("Missed openning %s", stream_nr)

        
    def readStream(self, syscall, retcode, args):
        """Parse a read action on a stream"""
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            stream._metadata['in'] += retcode
            if self.show_text:
                read_str =  self.parseString(syscall, retcode, args[1])
                if len(stream) > 1 and stream[-2].startswith(StatStreams.IN_MARKER):
                    #merge with last one                                                       
                    stream[-1] += read_str 
                else:
                    stream.append(StatStreams.IN_MARKER)
                    stream.append(read_str)
        else:
            logging.error("Missed openning %s", stream_nr)
            

    def writeStream(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            stream._metadata['out'] += retcode

            if self.show_text:
                write_str =  self.parseString(syscall, retcode, args[1])
                if len(stream) > 1 and stream[-2].startswith(StatStreams.OUT_MARKER):
                    #merge with last one
                    stream[-1] += write_str 
                else:
                    #new communication direction, start new block
                    stream.append(StatStreams.OUT_MARKER)
                    stream.append(write_str)  
        else:
            logging.error("Missed openning %s", stream_nr)

    def parseString(self, syscall, retcode, str_to_parse):
        """Parse a string from an read/write operation as output by strace"""
        #strip quotes and escape sequences
        str_arg = str_to_parse[1:-1].decode("string_escape")
        if StatStreams.RE_PAT['no_str'].search(str_arg):
            #handle a non printable string
            if self.show_binary:
                str_arg = self.prettyPrintHex(str_arg)
            else:
                str_arg = '<binary data>'
        if retcode > len(str_arg):
            #we don't have everything. Mark missing
            str_arg += '...\n'
        return str_arg
        
    def prettyPrintHex(self, src, length=16):
        """Pretty print binary data passed from parseString"""
        src = StatStreams.RE_PAT['no_ascii'].sub('.', src)
        offset=0
        result=''
        while src:
           s,src = src[:length],src[length:]
           hexa = ' '.join(["%02X"%ord(x) for x in s])
           result += "%04X   %-*s   %s\n" % (offset, length * 3, hexa, s)
           offset += length
        return result


    def closeStream(self, syscall, retcode, args):
        stream_nr = int(args[0])
        if stream_nr in self._open_streams:
            stream = self._open_streams[stream_nr]
            closing_strs = ['closed(%d) - in:%d - out: %d\n' % 
                (stream_nr, stream._metadata['in'], stream._metadata['out'])]

            if self.show_online:
                #just show the report and continue
                print '\n'.join(stream + closing_strs)
            else:
                #store the report for later
                self._closed_streams.append('\n'.join(stream + closing_strs))

            del self._open_streams[stream_nr]
        else:
            logging.error("Missed openning %d", stream_nr)

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
        if self.show_online:
            print "====== Finalized Streams  ======"
        for stream in self._open_streams.keys():
            self.closeStream(None, None, [stream])


        if not self.show_online:
            print "====== File Streams ======"
            print '\n'.join(self._closed_streams)


