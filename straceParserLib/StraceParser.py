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
import getopt
import re
import traceback
import logging
from optparse import OptionParser
from datetime import timedelta, time, datetime
from collections import defaultdict


class StraceParser:
    """
    StraceParser

    This is the strace parser. It parses each system call lines into a dict, and 
    then call the registered stat modules to process. 

    The defination of dict: please refer to _parseLine
    """


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
        self._completeSyscallCallbackHook = defaultdict(list)
        self._rawSyscallCallbackHook = defaultdict(list)

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
        table[name].append(func)
        

    def startParse(self, reader, straceOptions):
        self._parse(reader, straceOptions)

    def autoDetectFormat(self, reader):
        """ autoDetectFormat - Detect the strace output line format, return a
            dict with following:

            straceOptions["havePid"] = True/False
            straceOptions["haveTime"] = ""/"t"/"tt"/"ttt"
            straceOptions["haveTimeSpent"] True/False
                
            It use peek() on the reader so it will not abvance the position of
            the stream.
        """
        buf = reader.buffer.peek(4096);

        failCount = 0
        for line in buf.split('\n'):
            if failCount == 3:
                return None
            if "unfinish" in line or "resume" in line:
                continue
            straceOptions = self._detectLineFormat(line)
            if straceOptions:
                return straceOptions
            else:
                failCount += 1
        return None

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
        haveTime = ""
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
                    haveTime = ""

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




    def _parse(self, reader, straceOptions):
        syscallListByPid = {}

        unfinishedSyscallStack = {}
        if not reader:
            logging.error("Cannot read file")
            return

        for line in reader:

            if "restart_syscall" in line:      # TODO: ignore this first
                continue

            if "+++ exited with" in line:
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
#   return :    return value (+/- int string or hex number string or '?' (e.g. exit syscall)), not exist if it is an unfinished syscall
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

            if straceOptions["haveTime"] != "":
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
                    result["timeSpent"] = self._timeStrToDelta(m.group(1))
                else:
                    result["timeSpent"] = None

        except AttributeError:
            logging.warning("_parseLine: Error parsing this line: " + line)
            print sys.exc_info()
            #exctype, value, t = sys.exc_info()
            #print traceback.print_exc()
            #print sys.exc_info()
            return 
            
        return result

    def _countPrecedingBackslashes(self, s, pos):
        initialPos = pos
        while pos > 0 and s[pos-1] == '\\':
            pos-=1
        return (initialPos-pos)

    def _parseStringArg(self, argString):
        """
        Parses to the end of a string parameter.

        argString must begin with a quote character. _parseStringArg() parses
        to the corresponding terminating quote character.
        Returns the parsed string (including quotes) and the unparsed
        remainder of argString.

        >>> parser = StraceParser()
        >>> parser._parseStringArg('"abc"')
        ('"abc"', '')
        >>> parser._parseStringArg('"abc", 42') # the part behind the initial string will be returned as "remainder":
        ('"abc"', ', 42')
        >>> parser._parseStringArg('"", "42"')
        ('""', ', "42"')
        >>> parser._parseStringArg('"abc\"hello\"xyz", 42')
        ('"abc"', 'hello"xyz", 42')
        >>> parser._parseStringArg(r'"abc\x5c\x5c\x5c"xyz", 42') # multiple backslashes before terminating quote
        ('"abc\x5c\x5c\x5c\x5c\x5c\x5c"xyz"', ', 42')
        >>> print parser._parseStringArg(r'"\x5c\x5c\x5c"", 42')
        ('"\x5c\x5c\x5c\x5c\x5c\x5c""', ', 42')
        >>> print parser._parseStringArg(r'"\x5c\x5c", 42')
        ('"\x5c\x5c\x5c\x5c"', ', 42')
        >>> parser._parseStringArg('"abc') # bad parameter
        ('"', 'abc')
        """
        searchEndSymbolStartAt = 1
        while True:
            endSymbolIndex = argString.find('"', searchEndSymbolStartAt)

            if endSymbolIndex == -1:
                logging.warning("_parseStringArg: strange, can't find end symbol in this arg:" + argString)
                endSymbolIndex = 0
                break

            numPrecedingBackslashes = self._countPrecedingBackslashes(argString, endSymbolIndex)
            if numPrecedingBackslashes % 2 == 1:
                # if preceded by an odd number of backslashes, the quote character is escaped
                searchEndSymbolStartAt = endSymbolIndex + 1
            else:
                break
        return ( argString[0:endSymbolIndex+1], argString[endSymbolIndex+1:] )

    def _parseBlockArg(self, argString, parseBlock=False):
        """
        Parses a list of arguments, recursing into blocks.

        argString must be a string of comma-separated arguments.
        If parseBlock is True, argString must start with [ or {,
        and _parseBlockArg() will only parse to the end of the matching
        bracket.
        Returns the parsed arguments and the unparsed remainder of argString.

        >>> parser = StraceParser()
        >>> parser._parseBlockArg('[42]', True)
        (['42'], '')
        >>> parser._parseBlockArg('[]', True)
        ([''], '')
        >>> parser._parseBlockArg('[], []', True)
        ([''], ', []')
        >>> parser._parseBlockArg('[42, 5, "abc"]', True)
        (['42', '5', '"abc"'], '')
        >>> parser._parseBlockArg('[42, {5, 6}, "abc"], "xyz"', True)
        (['42', ['5', '6'], '"abc"'], ', "xyz"')
        >>> parser._parseBlockArg('{42, [5, "abc"}', True) # error case
        ('{42, [5, "abc"}', '')

        >>> parser._parseBlockArg('42')
        (['42'], '')
        >>> parser._parseBlockArg('5, 42')
        (['5', '42'], '')
        >>> parser._parseBlockArg('[[["[[]]"]]]')
        ([[[['"[[]]"']]]], '')
        """
        endSymbols = {'{':'}', '[':']', '"':'"'}
        resultArgs = []

        currIndex = 0
        if parseBlock:
            endChar = endSymbols[argString[0]]
            currIndex+=1

        lengthArgString = len(argString)
        remainderString = argString
        while currIndex < lengthArgString:
            if argString[currIndex] == ' ': # ignore space
                currIndex += 1
                continue

            content = None
            if argString[currIndex] == '"':
                # inner string; parse recursively till end of string
                (content, remainderString) = self._parseStringArg(argString[currIndex:])
            elif argString[currIndex] in ['{', '[']:
                # inner block; parse recursively till end of this block
                (content, remainderString) = self._parseBlockArg(argString[currIndex:], True)
            else:
                # normal parameter; find next comma
                remainderString = argString[currIndex:]

            nextCommaPos = remainderString.find(', ')
            if parseBlock:
                nextTerminatorPos = remainderString.find(endChar)
                if nextTerminatorPos == -1:
                    logging.warning("_parseBlockArg: strange, can't find end symbol '%s' in this arg: '%s'" % (endChar, argString))
                    return (argString, "")
            else:
                nextTerminatorPos = lengthArgString

            finished = False
            if nextCommaPos == -1 or nextTerminatorPos < nextCommaPos:
                # we've parsed last parameter in block
                contentString = remainderString[:nextTerminatorPos]
                remainderString = remainderString[nextTerminatorPos+1:]
                finished = True
            elif nextTerminatorPos > nextCommaPos:
                # there is another parameter in this block:
                contentString = remainderString[:nextCommaPos]
                remainderString = remainderString[nextCommaPos+1:]
            else:
                assert False, "internal error (this case shouldn't be hit)"

            if content is None:
                # block parser didn't return any value, or current parameter is a non-block value;
                # so use entire raw string as "content"
                content = contentString

            resultArgs.append(content)

            if finished:
                break

            assert(remainderString)
            currIndex = len(argString) - len(remainderString)
            currIndex+=1

        return (resultArgs, remainderString)

    def _parseArgs(self, argString):
        """
        Parses an argument string and returns a (possibly nested) list of arguments.

        >>> parser = StraceParser()
        >>> parser._parseArgs('42')
        ['42']
        >>> parser._parseArgs('5, 42')
        ['5', '42']

        >>> parser._parseArgs('5, FIONREAD, [0]')
        ['5', 'FIONREAD', ['0']]
        >>> parser._parseArgs('4, [{"ab, c]def", 9}, {"", 0}], 2')
        ['4', [['"ab, c]def"', '9'], ['""', '0']], '2']
        """
        endSymbol = {'{':'}', '[':']', '"':'"'}
        # short-cut: if there is no {, [, " in the whole argString, use split
        if all([sym not in argString for sym in endSymbol.keys()]):
            # remove the comma and space at the end of argString, then split
            # it by ', '
            resultArgs = argString.rstrip(' ,').split(', ')
            # remove all empty split
            return filter(len, resultArgs) 

        # otherwise, use a complex method to break the argument list, in order
        # to ensure the comma inside {}, [], "" would not break things.
        (content, remainderString) = self._parseBlockArg(argString, False)
        assert not(remainderString), "remainder left after parsing: '%s'" % remainderString
        return content


if __name__ == '__main__':
    print "running some tests..."
    import doctest
    doctest.testmod()

