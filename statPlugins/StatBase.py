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



class StatBase(object):
    """ The base class of stat plugins """

    def optionHelp(self):
        """ Should return a dict for all options for this plugin.
            The dict keys are the option names and dict Values are the 
            description of the options.
            E.g. {"output":"Write the output to this file instead of stdout"}

            It will be used for a help text in the command line. And it will
            be used to check if user input a correct option: If an
            option is specified for this plugin by user but it is not specified
            here, the command line will show error.
        """
        return {}

    def setOption(self, pluginOptionDict):
        """ The pluginOptionDict contains the key value pair of options for
            specified by user in the command line for this plugin.
            E.g. {"output":"/tmp/output.txt"}

            If no option specified, pluginOptionDict will be an empty dict ({}).
            Return False if there is some problem in the options so that this
            plugin would not be used.
        """
        return True

    def isOperational(self, straceOptions):
        """ Should return true if this plugin works in the current strace 
            options.
            The straceOptions should be a dict contains at least:
            straceOptions["havePid"] = 1/0
            straceOptions["haveTime"] = "", "t", "tt", or "ttt"
            straceOptions["haveTimeSpent"] = 1/0

            If isOperational return false, the register function will not be
            called.
        """
        return True

    def getSyscallHooks(self):
        """ Hook the processing function for each completed syscall. 

            The uncomplete/resumed syscall will be merged before passing to the
            hook function. And if it cannot merged then it will be ignored.
            (If you want to get uncomplete/resumed saperately, use 
             getRawSyscallHooks instead.)

            Should return a dict with key = syscall name and value = hook function
            E.g. return_dict["open"] = self.funcHandleOpenSyscall
                 return_dict["close"] = self.funcHandleCloseSyscall
                 return_dict["ALL"] = self.funcHandleALLSyscall
        """
        return None

    def getRawSyscallHooks(self):
        """ Hook the processing function for each syscall (which may be 
            unfinished/resumed)

            Should return a dict similar to that of getSyscallHooks
        """
        return None

    def printOutput(self):
        """ Should print the output to console. Would be called after parsing is 
            finished.
        """
        pass
