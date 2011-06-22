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

from datetime import timedelta, datetime

from StatBase import StatBase
from StatProcessTree import StatProcessTree


class StatFutex(StatBase):
    """ Get futex related info  """

    def __init__(self):
        self._statProcessTree = StatProcessTree()
        self._unfinishedResult = {}
        self._futexHolderPid = {}
        self._futexWaiterPids = {}

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
                if futexAddress in self._futexWaiterPids:
                    self._futexWaiterPids[futexAddress].append(pid)
                else:
                    self._futexWaiterPids[futexAddress] = [pid]

                print "{0} pid:{1} wait        futex:{2}, current holder:{3}, waiting list:{4}".format(
                       timeStr, pid, futexAddress, 
                       self._futexHolderPid[futexAddress] if futexAddress in self._futexHolderPid else "Unknown", 
                       self._futexWaiterPids[futexAddress])

            else: # completed or resumed = being wake up or timeout
                # remove myself from futexWaiterPids
                if futexAddress in self._futexWaiterPids:
                    if pid in self._futexWaiterPids[futexAddress]:
                        self._futexWaiterPids[futexAddress].remove(pid)

                returnValue = result["return"]
                if int(returnValue) == 0: # being wake up
                    self._futexHolderPid[futexAddress] = pid    # I am the holder now
                    print "{0} pid:{1} hold        futex:{2}, waiting list:{3}".format(
                           timeStr, pid, futexAddress, 
                           self._futexWaiterPids[futexAddress] if futexAddress in self._futexWaiterPids else "None")
                else:                # timeout 
                    print "{0} pid:{1} timeout     futex:{2}".format(timeStr, pid, futexAddress)
                    #TODO: many different cases in man page

        if "FUTEX_WAKE" in futexOp:
            self._futexHolderPid[futexAddress] = None
            print "{0} pid:{1} release     futex:{2}, waiting list:{3}".format(
                   timeStr, pid, futexAddress, 
                   self._futexWaiterPids[futexAddress] if futexAddress in self._futexWaiterPids else None)


    def printOutput(self):
        futexAddressSet = set(self._futexHolderPid.keys() + self._futexWaiterPids.keys())

        print "Futex Address,Holder,Waiters"
        for addr in futexAddressSet:
            print "{0},{1},{2}".format(addr, 
                   self._futexHolderPid[addr] if addr in self._futexHolderPid else "Unknown",
                   self._futexWaiterPids[addr] if addr in self._futexWaiterPids else "None")
