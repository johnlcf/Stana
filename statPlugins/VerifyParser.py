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
        if "pid" in result:
            pid = result["pid"]
        else:
            pid = ""
        if "startTime" in result:
            startTime = result["startTime"].time()
        else:
            startTime = ""

        if result["type"] == "resumed":
            output = "{0:<5} {1} <... {2} resumed> ".format(pid, startTime, result["syscall"])
        else:
            output = "{0:<5} {1} {2}(".format(pid, startTime, result["syscall"])
        output += ", ".join([str(a) for a in result["args"]])
        if result["type"] == "unfinished":
            output = output + " <unfinished ...>"
        else:
            output += ")"
            # pad some space before return value if it is too short
            # in order to match to original strace output
            output = "{0:<39} = {1}".format(output, result["return"])
            if "timeSpent" in result and result["timeSpent"]:
                output += " <%d.%06d>" % (result["timeSpent"].seconds, result["timeSpent"].microseconds)

        print output
        ## Print arg for check 
        #for arg in result["args"]:
        #    print "        '%s'" % arg

    def printOutput(self):
        pass
