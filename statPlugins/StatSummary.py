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
from collections import defaultdict
from datetime import timedelta

class StatSummary(StatBase):
    """ Summarize of syscall of strace, like strace -c output"""

    def __init__(self):
        self._syscallCount = defaultdict(int)
        self._syscallTime = defaultdict(timedelta)
        #self._syscallErrorCount = {}
        return

    def getSyscallHooks(self):
        return {"ALL": self.record}

    def isOperational(self, straceOptions):
        if not straceOptions["haveTimeSpent"]:
            return False
        return True

    def record(self, result):
        self._syscallCount[result["syscall"]] += 1
        if result["timeSpent"]:
            self._syscallTime[result["syscall"]] += result["timeSpent"]
        


    def printOutput(self):
        print "% time     seconds  usecs/call     calls syscall"
        print "------ ----------- ----------- --------- ----------------"

        totalCount = sum(self._syscallCount.values())
        totalTime = reduce(lambda x,y: x+y, self._syscallTime.values())
        for syscall in sorted(self._syscallTime, key=self._syscallTime.get,
                              reverse=True):
            percent = self._syscallTime[syscall].total_seconds() * 100 /  \
                        totalTime.total_seconds() 
            usecsPerCall = self._syscallTime[syscall] / \
                            self._syscallCount[syscall]
            print "%6.2f %11.6f %11d %9d %s" %            \
                  (percent, self._syscallTime[syscall].total_seconds(), 
                   usecsPerCall.total_seconds()*(10**6), 
                   self._syscallCount[syscall], syscall)
            
        print "------ ----------- ----------- --------- ----------------"
        print "%6.2f %11.6f %11d %9d %s" % (100, totalTime.total_seconds(), 
                totalTime.total_seconds()*(10**6) / totalCount, totalCount, "total")

