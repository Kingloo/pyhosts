import os
import sys
import logging
import requests
from collections import OrderedDict
from typing import List

class UnknownServerTypeError(Exception):
	""" Raised when the (REQUIRED) DNS server type is not recognised/supported by pyhosts """
	def __init__(self, unknownServerType) -> None:
		self._unknownServerType = unknownServerType
		super().__init__(self.unknownServerType)
	@property
	def unknownServerType(self):
		return self._unknownServerType
	def __str__(self) -> str:
		return self.message

class UsageError(Exception):
	""" Raised when the command line arguments don't match required usage """
	def __init__(self, message) -> None:
		self._message = message
		super().__init__(self.message)
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

class DownloadError(Exception):
	""" Raised when downloading a source return an HTTP status code other than 200 """
	def __init__(self, source, status_code) -> None:
		self._source = source
		self._status_code = status_code
		self._message = "{} ({})".format(source, status_code)
		super().__init__(self.message)
	@property
	def source(self):
		return self._source
	@property
	def status_code(self):
		return self._status_code
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

class NoSourcesConfiguredError(Exception):
	""" Raised when there are no sources configured """
	def __init__(self) -> None:
		self._message = "there are no sources configured"
		super().__init__(self.message)
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

class FileWritingError(Exception):
	""" Raised when the output file could not be written to """
	def __init__(self, filename) -> None:
		self._message = "file could not be written to: {}".format(filename)
		super().__init__(self.message)
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

class LocalhostFoundError(Exception):
	""" Raised when localhost found its way to a formatter """
	def __init__(self) -> None:
		self._message = "tried to pass localhost to a formatter"
		super().__init__(self.message)
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

def excludeUnwantedLines(lines):
	wantedLines = []
	for line in lines:
		isComment = line.startswith("#")
		isEmpty = len(line) == 0
		isLocalhost = line == "localhost"
		isWanted = isComment == False and isEmpty == False and isLocalhost == False
		if isWanted:
			wantedLines.append(line)
	return wantedLines

class MVPS():
	def __init__(self) -> None:
		self._name = "MVPS"
		self._url = "http://winhelp2002.mvps.org/hosts.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		wantedLines = excludeUnwantedLines(lines)
		for line in wantedLines:
			line = str.replace(line, "0.0.0.0 ", "")
			line = line.partition("#")[0] # removes trailing comment if present
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogAdGuardDNS():
	def __init__(self) -> None:
		self._name = "Firebog AdGuard DNS"
		self._url = "https://v.firebog.net/hosts/AdguardDNS.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentAds():
	def __init__(self) -> None:
		self._name = "Firebog Prigent Ads"
		self._url = "https://v.firebog.net/hosts/Prigent-Ads.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentCrypto():
	def __init__(self) -> None:
		self._name = "Firebog Prigent Crypto"
		self._url = "https://v.firebog.net/hosts/Prigent-Crypto.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentMalware():
	def __init__(self) -> None:
		self._name = "Firebog Prigent Malware"
		self._url = "https://v.firebog.net/hosts/Prigent-Malware.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogAdmiral():
	def __init__(self) -> None:
		self._name = "Firebog Admiral"
		self._url = "https://v.firebog.net/hosts/Admiral.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogEasyPrivacy():
	def __init__(self) -> None:
		self._name = "Firebog Easy Privacy"
		self._url = "https://v.firebog.net/hosts/Easyprivacy.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class UnboundFormatter:
	def __init__(self) -> None:
		self.list = []
	def format(self, lines: List[str]) -> List[str]:
		pass
	def __str__(self) -> str:
		return "Unbound Formatter"

class BindFormatter:
	def __init__(self) -> None:
		self.list = []
	def format(self, lines: List[str]) -> List[str]:
		pass
	def __str__(self) -> str:
		return "BIND Formatter"

class WindowsHostsFileFormatter:
	def __init__(self) -> None:
		self.list = []
	def format(self, lines: List[str]) -> List[str]:
		formatted = ["127.0.0.1 localhost", "::1 localhost", ""]
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = "0.0.0.0 {}".format(line)
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return "Windows Hosts File Formatter"

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
