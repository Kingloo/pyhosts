import os
import sys
import logging
import requests
from collections import OrderedDict
from formatters import *
from sources import *
from exceptions import *

def getSources():
	return [
		MVPS(),
		FirebogAdGuardDNS(),
		FirebogPrigentAds(),
		FirebogPrigentMalware(),
		FirebogPrigentCrypto(),
		FirebogAdmiral(),
		FirebogEasyPrivacy()
	]

def downloadSource(session: requests.Session, source) -> List[str]:
	response = session.get(source.url)
	if response.status_code is not 200:
		raise DownloadError(source, response.status_code)
	return response.text.splitlines()

def createSourceDownloadSummary(source, count) -> str:
	longestNameLength = max(len(s.name) for s in getSources())
	paddingRequired = longestNameLength - len(source.name)
	padding = " " * paddingRequired # creates a string of empty spaces of paddingRequired's length
	return "-\t{}{}\t{}".format(source.name, padding, count)

def downloadSources(sources) -> List[str]:
	if len(sources) == 0:
		raise NoSourcesConfiguredError()
	lines = []
	with requests.Session() as session:
		printError("begin downloading from {} sources".format(len(sources)))
		for source in sources:
			downloadedLines = downloadSource(session, source)
			formattedLines = source.format(downloadedLines)
			for line in formattedLines:
				lines.append(line)
			printError(createSourceDownloadSummary(source, len(formattedLines)))
		printError("finished downloading ({} total)".format(len(lines)))
	return list(set(lines)) # removes duplicates

def combineWithScriptDirectory(filename):
	return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def readFile(path) -> List[str]:
	with open(path, "r") as file:
		lines = file.readlines()
		for line in file:
			if not line.startswith("#") and len(line) > 0:
				lines.append(line)
		return lines

def loadWhitelist() -> List[str]:
	whitelistPath = combineWithScriptDirectory("whitelist.txt")
	try:
		whitelist = readFile(whitelistPath)
		printError("loaded {} whitelisted domain(s)".format(len(whitelist)))
		return whitelist
	except FileNotFoundError:
		printError("no whitelist file found")
	return []

def loadBlacklist() -> List[str]:
	blacklistPath = combineWithScriptDirectory("blacklist.txt")
	try:
		blacklist = readFile(blacklistPath)
		printError("loaded {} blacklisted domain(s)".format(len(blacklist)))
		return blacklist
	except FileNotFoundError:
		printError("no blacklist file found")
	return []

def writeLinesToStdOut(lines: List[str]):
	print("\n".join(lines), file=sys.stdout)

def writeLinesToFile(lines, filename):
	if len(lines) > 0:
		with open(filename, "w") as file:
			if file.writable:
				file.write("\n".join(lines))
			else:
				raise FileWritingError(filename)
	else:
		printError("no lines to write")

def writeLines(lines, filename):
	if filename is None:
		writeLinesToStdOut(lines)
	else:
		writeLinesToFile(lines, filename)

def process(serverFormatter, filename):
	printError("using {} and saving to {}".format(str(serverFormatter), filename))
	lines = []
	for blacklisted in loadBlacklist():
		lines.append(blacklisted)
	try:
		for downloaded in downloadSources(getSources()):
			lines.append(downloaded)
		printError("downloaded {} distinct domains".format(len(lines)))
	except DownloadError as e:
		printError("downloading failed ({})".format(e.message))
		sys.exit(-1)
	distinctLines = list(OrderedDict.fromkeys(lines))
	countWhitelistSaved = 0
	for whitelisted in loadWhitelist():
		if whitelisted in distinctLines:
			distinctLines.remove(whitelisted)
			countWhitelistSaved = countWhitelistSaved + 1
	if countWhitelistSaved > 0:
		printError("{} domain(s) saved via whitelisting".format(countWhitelistSaved))
	formattedForServer = serverFormatter.format(distinctLines)
	writeLines(formattedForServer, filename)

def determineServerFormatter(serverArg: str):
	serverArgLower = serverArg.lower()
	if serverArgLower == "unbound":
		return UnboundFormatter()
	elif serverArgLower == "bind":
		return BindFormatter()
	elif serverArgLower == "winhosts":
		return WindowsHostsFileFormatter()
	else:
		raise UnknownServerTypeError(serverArg)

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
