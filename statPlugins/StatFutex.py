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

import sys
from datetime import timedelta, datetime
from collections import defaultdict

from StatBase import StatBase
from StatProcessTree import StatProcessTree


class StatFutex(StatBase):
    """ Get futex related info  """

    def __init__(self):
        self._statProcessTree = StatProcessTree()
        self._unfinishedResult = {}
        self._futexHolderPid = {}
        self._futexWaiterPids = defaultdict(list)
        self._pluginOptionDict = {}
        self._outputFile = sys.stdout

    def optionHelp(self):
        return {"output":"Write the output to this file instead of stdout"}

    def setOption(self, pluginOptionDict):
        self._pluginOptionDict = pluginOptionDict
        filename = self._pluginOptionDict.get("output", "")
        self._outputFile = open(filename, "w") if filename else sys.stdout
        return True

    def isOperational(self, straceOptions):
        self._straceOptions = straceOptions
        return True

    def getSyscallHooks(self):
        if self._straceOptions["havePid"]:
            return self._statProcessTree.getSyscallHooks()
        else:
            return None

    def getRawSyscallHooks(self):
        if self._straceOptions["havePid"]:
            return {"futex": self.funcHandleFutexSyscall}
        return None

    def funcHandleFutexSyscall(self, result):
        #print result
        pid = result["pid"]
        syscallType = result["type"]
        timeStr = result["startTime"].time()

        if syscallType == "resumed":
            # if this is a resume syscall, combine it with last unfinished syscall of this pid
            lastResult = self._unfinishedResult[pid]
            lastResult["return"] = result["return"]
            lastResult["args"].append(result["args"])
            lastResult["type"] = "completed"
            result = lastResult
        elif syscallType == "unfinished":
            self._unfinishedResult[pid] = result

        futexAddress = result["args"][0]
        futexOp = result["args"][1]
        if "FUTEX_WAIT" in futexOp:
            if syscallType == "unfinished": # wait on a futex
                # add myself in waiter list
                self._futexWaiterPids[futexAddress].append(pid)

                self._outputFile.write("{0} pid:{1} wait        futex:{2}, current holder:{3}, waiting list:{4}\n".format(
                       timeStr, pid, futexAddress, 
                       self._futexHolderPid[futexAddress] if futexAddress in self._futexHolderPid else "Unknown", 
                       self._futexWaiterPids[futexAddress]))

            else: # completed or resumed = being wake up or timeout
                # remove myself from futexWaiterPids
                if futexAddress in self._futexWaiterPids:
                    if pid in self._futexWaiterPids[futexAddress]:
                        self._futexWaiterPids[futexAddress].remove(pid)

                returnValue = result["return"]
                if int(returnValue) == 0: # being wake up
                    self._futexHolderPid[futexAddress] = pid    # I am the holder now
                    self._outputFile.write("{0} pid:{1} hold        futex:{2}, waiting list:{3}\n".format(
                           timeStr, pid, futexAddress, 
                           self._futexWaiterPids[futexAddress]))
                else:                # timeout 
                    self._outputFile.write("{0} pid:{1} timeout     futex:{2}\n".format(timeStr, pid, futexAddress))
                    #TODO: many different cases in man page

        if "FUTEX_WAKE" in futexOp:
            self._futexHolderPid[futexAddress] = None
            self._outputFile.write("{0} pid:{1} release     futex:{2}, waiting list:{3}\n".format(
                   timeStr, pid, futexAddress, 
                   self._futexWaiterPids[futexAddress]))


    def printOutput(self):
        futexAddressSet = set(self._futexHolderPid.keys() + self._futexWaiterPids.keys())

        self._outputFile.write("Futex Address,Holder,Waiters\n")
        for addr in futexAddressSet:
            self._outputFile.write("{0},{1},{2}\n".format(addr, 
                   self._futexHolderPid[addr] if addr in self._futexHolderPid else "Unknown",
                   self._futexWaiterPids[addr]))
