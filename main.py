import os
import sys
import logging
import requests
from typing import List
from collections import OrderedDict
from formatters import determineServerFormatter
from sources import getSources, downloadSources
from exceptions import DownloadError, FileReadError, FileWriteError, UsageError


def combineWithScriptDirectory(filename):
	thisScriptsDirectory = os.path.dirname(os.path.abspath(__file__))
	return os.path.join(thisScriptsDirectory, filename)


def loadWhitelist() -> List[str]:
	whitelistPath = combineWithScriptDirectory("whitelist.txt")
	try:
		whitelist: List[str] = readLines(whitelistPath)
		printError("loaded {} whitelisted domain(s)".format(len(whitelist)))
		return whitelist
	except FileNotFoundError:
		printError("no whitelist file found")
	return []


def loadBlacklist() -> List[str]:
	blacklistPath = combineWithScriptDirectory("blacklist.txt")
	try:
		blacklist = readLines(blacklistPath)
		printError("loaded {} blacklisted domain(s)".format(len(blacklist)))
		return blacklist
	except FileNotFoundError:
		printError("no blacklist file found")
	return []


def removeDupes(lines: List[str]) -> List[str]:
	return list(OrderedDict.fromkeys(lines))


def readLines(path) -> List[str]:
	with open(path, "r") as file:
		if not file.readable:
			raise FileReadError(path)
		return list(filter(lambda x: not x.startswith("#") and len(x) > 0, file.read().splitlines()))


def writeLinesToStdOut(lines: List[str]):
	print("\n".join(lines), file=sys.stdout)


def writeLinesToFile(lines, filename):
	if len(lines) > 0:
		with open(filename, "w") as file:
			if not file.writable:
				raise FileWriteError(filename)
			file.write("\n".join(lines))
		printError("file written to {}".format(os.path.abspath(filename)))
	else:
		printError("no lines to write")


def writeLines(lines, filename):
	if filename is None:
		writeLinesToStdOut(lines)
	else:
		writeLinesToFile(lines, filename)


def process(serverFormatter, filename):
	printError("using {}".format(serverFormatter.name))
	lines: List[str] = []
	lines.extend(loadBlacklist())
	try:
		downloaded = downloadSources(getSources())
		lines.extend(downloaded)
	except (DownloadError, requests.HTTPError) as e:
		printError("downloading failed ({})".format(e.message))
		sys.exit(-1)
	uniqueLines = removeDupes(lines)
	printError("finished downloading ({} total, {} unique)".format(len(lines), len(uniqueLines)))
	savedViaWhitelist = []
	for whitelisted in loadWhitelist():
		if whitelisted in uniqueLines:
			uniqueLines.remove(whitelisted)
			savedViaWhitelist.append(whitelisted)
	if len(savedViaWhitelist) > 0:
		printError("{} domain(s) saved via whitelisting ({})".format(len(savedViaWhitelist), ", ".join(savedViaWhitelist)))
	else:
		printError("no domains saving via whitelisting")
	formattedForServer = serverFormatter.format(uniqueLines)
	writeLines(formattedForServer, filename)


def parseArguments(args):
	if len(args) < 1:
		print(getUsage())
		raise UsageError("too few arguments")
	serverFormatter = determineServerFormatter(args[0])
	if len(args) >= 2:
		if os.path.exists(args[1]):
			raise FileExistsError(args[1])
		filename = args[1]
	else:
		filename = None
	return (serverFormatter, filename)


def printError(message: str):
	print(message, file=sys.stderr)


def getUsage():
	return """USAGE:
first argument is DNS server type (REQUIRED): unbound, bind, winhosts
second argument is output filename (OPTIONAL) """


def main(args: List[str]):
	try:
		(serverFormatter, filename) = parseArguments(args)
		process(serverFormatter, filename)
	except Exception as e:
		logging.getLogger(__name__).exception(e)
		sys.exit(-1)


if __name__ == "__main__":
	main(sys.argv[1:])
