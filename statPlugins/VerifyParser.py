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

class VerifyParser(StatBase):
    """ For verify parser output """

    def getRawSyscallHooks(self):
        return {"ALL": self.funcHandleALLSyscall}

    def funcHandleALLSyscall(self, result):
        output = "{0:<5} {1} {2}(".format(result["pid"], result["startTime"], result["syscall"])
        output = output + ", ".join(result["args"])
        if "return" in result:
            output = output + ") = " + result["return"]
        else:
            output = output + " <unfinished ...>"
        print output
        ## Print arg for check 
        #for arg in result["args"]:
        #    print "        %s" % arg

    def printOutput(self):
        pass
