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
from datetime import timedelta, time, datetime


class StraceParser:
    """StraceParser     """


    def __init__(self):
        # _completeSyscallCallbackHook
        # the dict contains a list for each syscall that registered by someone who is
        # increased in the syscall is parsed.
        # E.g.
        #
        # _completeSyscallCallbackHook["open"] = [func1, func2]
        # _completeSyscallCallbackHook["close"] = [func1]
        # _completeSyscallCallbackHook["ALL"] = [func1]        'ALL' means it will be involved for all kind of syscalls
        #
        # 
        self._completeSyscallCallbackHook = {}
        self._rawSyscallCallbackHook = {}

        # regex compiled for _parseLine
        self._reCompleteSyscall = re.compile(r"([^(]+)\((.*)\)[ ]+=[ ]+([a-fx\d\-?]+)(.*)")
        self._reUnfinishedSyscall = re.compile(r"([^(]+)\((.*) <unfinished ...>")
        self._reResumedSyscall = re.compile(r"\<\.\.\. ([^ ]+) resumed\> (.*)\)[ ]+=[ ]+([a-fx\d\-?]+)(.*)")
        return

    def registerSyscallHook(self, fullSyscallName, func):
        self._registerHookInTable(fullSyscallName, self._completeSyscallCallbackHook, func)
        
    def registerRawSyscallHook(self, fullSyscallName, func):
        self._registerHookInTable(fullSyscallName, self._rawSyscallCallbackHook, func)

    def _registerHookInTable(self, name, table, func):
        if name in table:
            table[name].append(func)
        else:
            table[name] = [func]
        

    def startParse(self, filename, straceOptions):
        self._parse(filename, straceOptions)

    def autoDetectFormat(self, filename):
        """ autoDetectFormat - Detect the strace output line format, return a
            dict with following:

            straceOptions["havePid"] = True/False
            straceOptions["haveTime"] = None/"t"/"tt"/"ttt"
            straceOptions["haveTimeSpent"] True/False
                
        """
        f = open(filename)
        failCount = 0
        for line in f:
            if failCount == 3:
                f.close()
                return None
            if "unfinish" in line or "resume" in line:
                continue
            straceOptions = self._detectLineFormat(line)
            if straceOptions:
                f.close()
                return straceOptions
            else:
                failCount += 1

    def _detectTimeFormat(self, timeStr):
        if ":" not in timeStr and "." in timeStr:
            return "ttt"
        if ":" in timeStr:
            if "." in timeStr:
                return "tt"
            else:
                return "t"
        logging.debug("_detectTimeFormat: Failed: unable to detect time format.")
        return None

    def _detectLineFormat(self, line):
        havePid = False
        haveTime = None
        haveTimeSpent = False

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
            preList = pre.strip().split()
            if len(preList) > 2:
                logging.debug("_detectLineFormat: Failed: more the 2 parts in pre.")
                return
            if len(preList) == 2:
                haveTime = self._detectTimeFormat(preList[1])
                havePid = True
            else:
                if ':' in pre or '.' in pre:
                    havePid = False
                    haveTime = self._detectTimeFormat(preList[0])
                else:
                    havePid = True
                    haveTime = None

        if post != '':
            if re.search(r"(<[0-9.]+>)", line):
                haveTimeSpent = True
            else:
                haveTimeSpent = False
            
        straceOptions = {}    
        straceOptions["havePid"] = havePid
        straceOptions["haveTime"] = haveTime
        straceOptions["haveTimeSpent"] = haveTimeSpent

        return straceOptions




    def _parse(self, filename, straceOptions):
        syscallListByPid = {}

        unfinishedSyscallStack = {}
        f = open(filename, "r")
        if not f:
            logging.error("Cannot open file: " + filename)
            return

        for line in f:

            if "restart_syscall" in line:      # TODO: ignore this first
                continue

            unfinishedSyscall = False
            reconstructSyscall = False
            if "<unfinished ...>" in line:     # store the unfinished line for reconstruct
                unfinishedSyscall = True
                if straceOptions["havePid"]:
                    pid = (line.partition(" "))[0]
                    unfinishedSyscallStack[pid] = line
                else:
                    unfinishedSyscallStack[0] = line
            elif "resumed>" in line:         # get back the unfinished line and reconstruct
                if straceOptions["havePid"]:
                    pid = (line.partition(" "))[0]
                    if pid not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[pid]
                else:
                    if 0 not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[0] 
                lineIndex = line.find("resumed>") + len("resumed>")
                reconstructLine = existLine.replace("<unfinished ...>", line[lineIndex:])
                reconstructSyscall = True
                #print "debug reconstructed line:", line


            # Parse the line
            #print line
            result = self._parseLine(line, straceOptions)

            # hook here for every (raw) syscalls
            if result:
                if result["syscall"] in self._rawSyscallCallbackHook:
                    for func in self._rawSyscallCallbackHook[result["syscall"]]:
                        func(result)
                if "ALL" in self._rawSyscallCallbackHook:
                    for func in self._rawSyscallCallbackHook["ALL"]:
                        func(result)

            # determine if there is a completeSyscallResult
            if unfinishedSyscall:
                completeSyscallResult = None
            elif reconstructSyscall:
                completeSyscallResult = self._parseLine(reconstructLine, straceOptions)
            else:   # normal completed syscall
                completeSyscallResult = result

            # hook here for every completed syscalls:
            if completeSyscallResult:
                if completeSyscallResult["syscall"] in self._completeSyscallCallbackHook:
                    for func in self._completeSyscallCallbackHook[completeSyscallResult["syscall"]]:
                        func(completeSyscallResult)
                if "ALL" in self._completeSyscallCallbackHook:
                    for func in self._completeSyscallCallbackHook["ALL"]:
                        func(completeSyscallResult)

        return 


    def _timeStrToTime(self, timeStr, timeFormat):
        """ _timeStrToTime

            timeFormat: "t"   = "%H:%M:%S"
                        "tt"  = "%H:%M:%S.%f"
                        "ttt" = "timestamp.%f"
        """
        if timeFormat == "ttt":
            return datetime.utcfromtimestamp(float(timeStr))
        else:
            timeList = timeStr.split(":")
            # in order to use datetime object for calculation, pad the time with 1970-1-1
            # TODO: should handle the day boundary case in _parse function
            if timeFormat == "tt":
                secondList = timeList[2].split(".")
                return datetime(1970, 1, 1, int(timeList[0]), int(timeList[1]), int(secondList[0]), int(secondList[1]))
            else:
                return datetime(1970, 1, 1, int(timeList[0]), int(timeList[1]), int(timeList[2]))

    def _timeStrToDelta(self, timeStr):
        return timedelta(seconds=float(timeStr))

#
#   _parseLine
#
#   It parse a complete line and return a dict with the following:
#   pid :       pid (if havePid enabled)
#   startTime : start time of the call (if haveTime enabled)
#   syscall :   system call function 
#   args :      a list of arguments ([] if no options)
#   return :    return value (+/- int or hex number string or '?' (e.g. exit syscall)), not exist if it is an unfinished syscall
#   timeSpent : time spent in syscall (if haveTimeSpent enable. But even so, it may not exist in some case (e.g. exit syscall) and None will be stored in this field)
#   type :      Type of syscall ("completed", "unfinished", "resumed")
#
#   Return null if hit some error
#
#   (Not implemented) signalEvent : signal event (no syscall, args, return)
#
    def _parseLine(self, line, straceOptions):
        result = {}    
        remainLine = line

        try:
            if straceOptions["havePid"]:
                result["pid"], remainLine = remainLine.split(None, 1)

            if straceOptions["haveTime"]:
                timeStr, remainLine = remainLine.split(None, 1)
                result["startTime"] = self._timeStrToTime(timeStr, straceOptions["haveTime"])

            if "--- SIG" in remainLine:        # a signal line
                #result["signalEvent"] = remainLine
                #return result
                ### Ignore signal line now
                return 
            
            # If it is unfinished/resumed syscall, still parse it but let the
            # caller (_parse) determine what to do
            if "<unfinished ...>" in remainLine:
                result["type"] = "unfinished"
                m = self._reUnfinishedSyscall.match(remainLine)
                result["syscall"] = m.group(1)
                result["args"] = self._parseArgs(m.group(2).strip()) # probably only partal arguments
            elif "resumed>" in remainLine:
                result["type"] = "resumed"
                m = self._reResumedSyscall.match(remainLine)
                result["syscall"] = m.group(1)
                result["args"] = self._parseArgs(m.group(2).strip()) # probably only partal arguments
                result["return"] = m.group(3)
                remainLine = m.group(4)
            else:
                # normal system call
                result["type"] = "completed"
                m = self._reCompleteSyscall.match(remainLine)
                result["syscall"] = m.group(1)
                result["args"] = self._parseArgs(m.group(2).strip())
                result["return"] = m.group(3)
                remainLine = m.group(4)

            if result["type"] != "unfinished" and straceOptions["haveTimeSpent"]:
                m = re.search(r"<([\d.]*)>", remainLine)
                if m:
                    result["timespent"] = _timeStrToDelta(m.group(1))
                else:
                    result["timespent"] = None

        except AttributeError:
            logging.warning("_parseLine: Error parsing this line: " + line)
            print sys.exc_info()
            #exctype, value, t = sys.exc_info()
            #print traceback.print_exc()
            #print sys.exc_info()
            return 
            
        return result

    def _parseArgs(self, argString):
        endSymbol = {'{':'}', '[':']', '"':'"'}
        resultArgs = []

        # short-cut: if there is no {, [, " in the whole argString, use split
        if all([sym not in argString for sym in endSymbol.keys()]):
            # remove the comma and space at the end of argString, then split
            # it by ', '
            resultArgs = argString.rstrip(' ,').split(', ')
            # remove all empty split
            return filter(len, resultArgs) 

        # otherwise, use a complex method to break the argument list, in order
        # to ensure the comma inside {}, [], "" would not break things.
        currIndex = 0
        lengthArgString = len(argString)
        while currIndex < lengthArgString:
            if argString[currIndex] == ' ':     # ignore space
                currIndex += 1
                continue
            
            if argString[currIndex] in ['{', '[', '"']:

                searchEndSymbolStartAt = currIndex+1    # init search from the currIndex+1
                while searchEndSymbolStartAt < lengthArgString:
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
                i = lengthArgString      # the last arg
            resultArgs.append(argString[currIndex:i]) # not include ','
            currIndex = i + 1           # point to the char after ','

        #print argString
        #print resultArgs
        return resultArgs

