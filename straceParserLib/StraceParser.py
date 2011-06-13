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


"""
StraceParser

This is the strace parser. It parses each system call lines into a dict, and 
then call the registered stat modules to process. 

The defination of dict: please refer to _parseLine
"""
import sys
import getopt
import re
import traceback
import logging
from optparse import OptionParser



class StraceParser:
    """StraceParser     """


    def __init__(self):
        # _syscallCallbackHook
        # the dict contains a list for each syscall that registered by someone who is
        # increased in the syscall is parsed.
        # E.g.
        #
        # _syscallCallbackHook["open"] = [func1, func2]
        # _syscallCallbackHook["close"] = [func1]
        # _syscallCallbackHook["ALL"] = [func1]        'ALL' means it will be involved for all kind of syscalls
        #
        # 
        self._syscallCallbackHook = {}
        return

    def registerSyscallHook(self, fullSyscallName, func):
        if fullSyscallName in self._syscallCallbackHook:
            self._syscallCallbackHook[fullSyscallName].append(func)
        else:
            self._syscallCallbackHook[fullSyscallName] = [func]
        
    def startParse(self, filename, options):
        if options.withpid or options.withtime or options.withtimespent:
            havePid = options.withpid
            haveTime = options.withtime
            haveTimeSpent = options.withtimespent
        else:
            f = open(filename)
            lineFormat = self._detectLineFormat(f.readline())
            if lineFormat:
                havePid, haveTime, haveTimeSpent = lineFormat
            else:
                logging.warning("Auto detect line format failed. Suggest using -t,-f,-T to specify.")
                havePid = 0
                haveTime = 0
                haveTimeSpent = 0
            f.close()
        self._parse(filename, havePid, haveTime, haveTimeSpent)


    def _detectLineFormat(self, line):
        havePid = 0
        haveTime = 0
        haveTimeSpent = 0

        remainLine = line

        m = re.match(r"([0-9:. ]*)([a-z]+\(.*[ ]+=[ ]+[-0-9]+)(.*)", line)
        if m:
            pre = m.group(1)
            mid = m.group(2)
            post = m.group(3)
        else:
            logging.debug("_detectLineFormat: Failed: unable to match the line, give up detection.")
            return

        if pre != '':
            if len(pre.strip().split()) > 2:
                logging.debug("_detectLineFormat: Failed: more the 2 parts in pre.")
                return
            if len(pre.strip().split()) == 2:
                haveTime = 1
                havePid = 1
            else:
                if ':' in pre or '.' in pre:
                    havePid = 0
                    haveTime = 1
                else:
                    havePid = 1
                    haveTime = 0

        if post != '':
            if re.search(r"(<[0-9.]+>)", line):
                haveTimeSpent = 1
            else:
                haveTimeSpent = 0
            
        return (havePid, haveTime, haveTimeSpent)




    def _parse(self, filename, havePid=0, haveTime=0, haveTimeSpent=0):
        syscallListByPid = {}

        unfinishedSyscallStack = {}
        f = open(filename, "r")
        if not f:
            logging.error("Cannot open file: " + filename)
            return

        for line in f:

            if line.find("restart_syscall") != -1:      # TODO: ignore this first
                continue

            if line.find("<unfinished ...>") != -1:     # store the unfinished line for reconstruct
                if havePid:
                    pid = (line.partition(" "))[0]
                    unfinishedSyscallStack[pid] = line
                else:
                    unfinishedSyscallStack[0] = line
                continue

            if line.find("resumed>") != -1:         # get back the unfinished line and reconstruct
                if havePid:
                    pid = (line.partition(" "))[0]
                    if pid not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[pid]
                else:
                    if 0 not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[0] 
                lineIndex = line.find("resumed>") + len("resumed>")
                line = existLine.replace("<unfinished ...>", line[lineIndex:])
                #print "debug reconstructed line:", line


            # Parse the line. The line should be a completed system call
            #print line
            result = self._parseLine(line, havePid, haveTime, haveTimeSpent)

            # hook here for every completed syscalls:
            if result:
                #print result
                if result["syscall"] in self._syscallCallbackHook:
                    for func in self._syscallCallbackHook[result["syscall"]]:
                        func(result)
                for func in self._syscallCallbackHook["ALL"]:
                    func(result)
            

        # hook here for final:
        #printFileIO()

        return 

#
#   _parseLine
#
#   It parse a complete line and return a dict with the following:
#   pid :       pid (if havePid enabled)
#   startTime : start time of the call (if haveTime enabled)
#   syscall :   system call function 
#   args :      a list of arguments ([] if no options)
#   return :    return value (number or '?' (e.g. exit syscall))
#   timeSpent : time spent in syscall (if haveTimeSpent enable. But even so, it may not exist in some case (e.g. exit syscall) )
#
#   Return null if hit some error
#
#   (Not implemented) signalEvent : signal event (no syscall, args, return)
#
    def _parseLine(self, line, havePid=0, haveTime=0, haveTimeSpent=0):
        result = {}    
        remainLine = line

        try:
            if havePid:
                m = re.match(r"(\d+)[ ]+(.*)", remainLine)
                result["pid"] = m.group(1)
                remainLine = m.group(2)
            if haveTime:
                m = re.match(r"([:.\d]+)[ ]+(.*)", remainLine)
                result["startTime"] = m.group(1)
                remainLine = m.group(2)

            if remainLine.find("--- SIG") != -1:        # a signal line
                #result["signalEvent"] = remainLine
                #return result
                ### Ignore signal line now
                return 
            
            ### assume no unfinished/resumed syscall, all are merged by caller
            if remainLine.find("<unfinished ...>") != -1 or remainLine.find("resumed>") != -1:
                return

            # normal system call
            m = re.match(r"([^(]+)\((.*)\)[ ]+=[ ]+([\d\-?]+)(.*)", remainLine)
            result["syscall"] = m.group(1)
            result["args"] = self._parseArgs(m.group(2).strip())
            result["return"] = m.group(3)
            remainLine = m.group(4)

            if haveTimeSpent:
                m = re.search(r"<([\d.]*)>", remainLine)
                if m:
                    result["timespent"] = m.group(1)
                else:
                    result["timespent"] = "unknown"

        except AttributeError:
            logging.warning("_parseLine: Error parsing this line: " + line)
            #print sys.exc_info()
            #exctype, value, t = sys.exc_info()
            #print traceback.print_exc()
            #print sys.exc_info()
            return 
            
        return result

    def _parseArgs(self, argString):
        endSymbol = {'{':'}', '[':']', '"':'"'}
        resultArgs = []
        currIndex = 0
        while currIndex < len(argString):
            if argString[currIndex] == ' ':     # ignore space
                currIndex += 1
                continue
            
            if argString[currIndex] in ['{', '[', '"']:

                searchEndSymbolStartAt = currIndex+1    # init search from the currIndex+1
                while searchEndSymbolStartAt < len(argString):
                    endSymbolIndex = argString.find(endSymbol[argString[currIndex]], searchEndSymbolStartAt)
                    if endSymbolIndex == -1:
                        logging.warning("_parseArgs: strange, can't find end symbol in this arg:" + argString)
                        return []
                    if argString[endSymbolIndex-1] == '\\' and (endSymbolIndex-2 >= 0 and argString[endSymbolIndex-2] != '\\'):  # escape char which are not escaped
                        searchEndSymbolStartAt = endSymbolIndex + 1
                    else:
                        break
                searchCommaStartAt = endSymbolIndex + 1
            else:    # normal, search comma after currIndex
                searchCommaStartAt = currIndex + 1

            i = argString.find(',', searchCommaStartAt)
            if i == -1:
                i = len(argString)      # the last arg
            resultArgs.append(argString[currIndex:i]) # not include ','
            currIndex = i + 1           # point to the char after ','

        #print argString
        #print resultArgs
        return resultArgs

