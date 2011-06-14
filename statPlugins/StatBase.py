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

    def isOperational(self, straceOptions):
        """ Return true if this plugin works in the current strace options.
            The straceOptions should be a dict contains at least:
            straceOptions["havePid"] = 1/0
            straceOptions["haveTime"] = 1/0
            straceOptions["haveTimeSpent"] = 1/0

            If isOperational return false, the register function will not be
            called.
        """
        return True

    def register(self, straceParser):
        """ Register my callback function to straceParser by 
            straceParser.registerSyscallHook 
        """
        pass

    def printOutput(self):
        """ Print the output to console. Would be called after parsing is 
            finished.
        """
        pass
