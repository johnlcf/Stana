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

from StatBase import StatBase

class StatFileIO(StatBase):
    """ Stat and print file IO of strace"""

    def __init__(self):
        self._fileStatList = {}
        self._fidStatList = {}
        return

    def register(self, straceParser):
        for syscall in ["read", "write", "open", "close"]:
            straceParser.registerSyscallHook(syscall, self.statFileIO)

    def statFileIO(self, result):
        if result["syscall"] in ["read", "write", "open", "close"]:
            if result["return"] == -1:  # ignore failed syscalls
                return
            
            if result["syscall"] == "open":
                fid = result["return"]
            else:
                fid = result["args"][0]

            # file close
            if result["syscall"] == "close":
                if fid in self._fidStatList:
                    #print self._fidStatList[fid]
                    filename = self._fidStatList[fid][0]
                    if filename not in self._fileStatList:
                        self._fileStatList[filename] = [1, 
                                                        self._fidStatList[fid][1], 
                                                        self._fidStatList[fid][2], 
                                                        self._fidStatList[fid][3], 
                                                        self._fidStatList[fid][4]]
                    else:
                        self._fileStatList[filename][0] += 1
                        for i in [1, 2, 3, 4]:
                            self._fileStatList[filename][i] += self._fidStatList[fid][i]

                    del self._fidStatList[fid]
                    return

            # if read/write/open
            if fid not in self._fidStatList:
                if result["syscall"] == "open":
                    # self._fidStatList[fid] = [filename, read count, read acc bytes, write count, write acc bytes]
                    self._fidStatList[fid] = [result["args"][0], 0, 0, 0, 0]
                else:
                    self._fidStatList[fid] = ["unknown:"+fid, 0, 0, 0, 0]

            # stat read/write
            if result["syscall"] == "read":
                self._fidStatList[fid][1] += 1
                self._fidStatList[fid][2] += int(result["return"])
            if result["syscall"] == "write":
                self._fidStatList[fid][3] += 1
                self._fidStatList[fid][4] += int(result["return"])
            return

    def printOutput(self):
        print "====== File IO summary (csv) ======"

        for fid in self._fidStatList:
            #print self._fidStatList[fid]
            filename = self._fidStatList[fid][0]
            if filename not in self._fidStatList:
                self._fileStatList[filename] = [1, self._fidStatList[fid][1], self._fidStatList[fid][2], self._fidStatList[fid][3], self._fidStatList[fid][4]]
            else:
                self._fileStatList[filename][0] += 1
                for i in [1, 2, 3, 4]:
                    self._fileStatList[filename][i] += self._fidStatList[fid][i]

        print "filename, open/close count, read count, read bytes, write count, write bytes"
        for file in self._fileStatList:
            print "%s, %d, %d, %d, %d, %d" % tuple([file] + self._fileStatList[file])

