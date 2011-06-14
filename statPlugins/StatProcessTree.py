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
from StatBase import StatBase


class StatProcessTree(StatBase):
    """ Print the process fork tree in the strace file """

    def __init__(self):
        self._allPid = set()
        self._childDict = {}
        self._childExecName = {}
        return

    def isOperational(self, straceOptions):
        if not straceOptions["havePid"]:
            return False
        return True

    def register(self, straceParser):
        straceParser.registerSyscallHook("ALL", self.statProcessTree)

    def statProcessTree(self, result):
        if "pid" not in result:
            logging.warning("statProcessTree: no pid info in line")
            return

        pid = result["pid"]
        self._allPid.add(pid)
        if result["syscall"] == "clone":
            childPid = result["return"]
            if pid in self._childDict:
                self._childDict[pid].append(childPid)
            else:
                self._childDict[pid] = [childPid]
            # Copy the execuation name of parent process to child process.
            # It will be overwritten by next execve call of child 
            if pid in self._childExecName:
                self._childExecName[childPid] = self._childExecName[pid]

        if result["syscall"] == "execve":
            self._childExecName[pid] = result["args"][0]

    def printOutput(self):
        # remove child pid in _allPid, so it contains only head pid 
        for childPidList in self._childDict.values():
            for childPid in childPidList:
                self._allPid.remove(childPid)

        print "====== Process Tree ======"
        for pid in self._allPid:
            self._printTree(pid, 0)
        print ""


    def _printTree(self, pid, indent):
        for i in xrange(0, indent):
            print "   ",

        if pid in self._childExecName:
            print "%s [%s]" % (pid, self._childExecName[pid])
        else:
            print "%s [unknown]" % pid

        if pid in self._childDict:
            for childPid in self._childDict[pid]:
                self._printTree(childPid, indent+1)
        return
