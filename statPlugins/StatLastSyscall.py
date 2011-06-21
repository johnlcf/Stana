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

from collections import deque
from datetime import timedelta, datetime

from StatBase import StatBase
from StatProcessTree import StatProcessTree


class StatLastSyscall(StatBase):
    """ Find the last few unfinished syscall of process  """

    def __init__(self):
        self._statProcessTree = StatProcessTree()
        self._lastSyscallStore = {}
        self._lastSyscallTime = {}

    def isOperational(self, straceOptions):
        self._straceOptions = straceOptions
        return True

    def getSyscallHooks(self):
        if self._straceOptions["havePid"]:
            return self._statProcessTree.getSyscallHooks()
        else:
            return None

    def getRawSyscallHooks(self):
        return {"ALL": self.funcHandleALLSyscall}

    def _reconstructStraceLine(self, result):
        # recontruct the strace line
        if self._straceOptions["haveTime"]:
            syscallLine = result["startTime"] + " "
        else:
            syscallLine = ""
        syscallLine += "{0} (".format(result["syscall"]) + ", ".join(result["args"])
        if result["type"] == "unfinished":
            syscallLine += " <unfinished ...>"
        else:
            syscallLine += ")"
            # pad some space before return value if it is too short
            # in order to match to original strace output
            syscallLine = "{0:<39} = {1}".format(syscallLine, result["return"])
        return syscallLine

    def _timeStrToDatetime(self, timeStr):
        if ":" not in timeStr and "." in timeStr:
            return datetime.utcfromtimestamp(float(timeStr))
        if ":" in timeStr:
            if "." in timeStr:
                timeFormat = "%H:%M:%S.%f"
            else:
                timeFormat = "%H:%M:%S"
            return datetime.strptime(timeStr, timeFormat)
        return None
            

    def funcHandleALLSyscall(self, result):
        if self._straceOptions["havePid"]:
            pid = result["pid"]
        else:
            pid = 0
        
        # store the last syscall time
        if self._straceOptions["haveTime"]:
            syscallTime = self._timeStrToDatetime(result["startTime"])
            self._lastSyscallTime[pid] = syscallTime
            self._latestTime = syscallTime

        if pid in self._lastSyscallStore:
            self._lastSyscallStore[pid].append(result)
            if len(self._lastSyscallStore[pid]) > 3:    # store last 3 syscalls
                self._lastSyscallStore[pid].popleft()
        else:
            self._lastSyscallStore[pid] = deque([result])


    def printOutput(self):
        for pid, syscallList in self._lastSyscallStore.iteritems():
            if self._straceOptions["haveTime"]:
                waitTime = self._latestTime - self._lastSyscallTime[pid]
            else:
                waitTime = ""
            # Ignore all the exited process
            if "exit" not in syscallList[-1]["syscall"]:
                #print pid, self._statProcessTree.getProcessExecName(pid), waitTime
                #for syscallResult in syscallList:
                #    print "   ", self._reconstructStraceLine(syscallResult)
                print pid, waitTime, self._reconstructStraceLine(syscallList[-1])
