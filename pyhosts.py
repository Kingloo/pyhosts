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

class FileWriteError(Exception):
	""" Raised when the output file could not be written to """
	def __init__(self, filename) -> None:
		self._message = "file could not be written to: {}".format(filename)
		super().__init__(self.message)
	@property
	def message(self):
		return self._message
	def __str__(self) -> str:
		return self.message

class FileReadError(Exception):
	""" Raised when file could not be read """
	def __init__(self, filename) -> None:
		self._message = "file could not be read: {}".format(filename)
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

def getSources():
	return [
		MVPS(),
		FirebogAdGuardDNS(),
		FirebogPrigentAds(),
		FirebogPrigentMalware(),
		FirebogPrigentCrypto(),
		FirebogAdmiral(),
		FirebogEasyPrivacy(),
		FirebogEasyList(),
		OSIntDigitalSide(),
		PolishFiltersTeamKADHosts(),
		PhishingArmyBlocklistExtended()
	]

def isComment(line: str) -> bool:
	return line.startswith('#')

def isEmpty(line: str) -> bool:
	return len(line) == 0

def isLocalhost(line: str) -> bool:
	return line == "localhost"

def containsDoubleDots(line: str) -> bool:
	"""
	exclude domains with double dots
	e.g. example..com
	"""
	# an alternative would be to remove the second dot
	# and accept the domain then
	return ".." in line

def isValid(line: str) -> bool:
	""" returns true if every validator returns false """
	return not any([ validator(line) for validator in validatorFuncs ])

validatorFuncs = [
	isComment,
	isEmpty,
	isLocalhost,
	containsDoubleDots
]

def removeTrailingDot(line: str) -> str:
	return line[:-1] if line.endswith('.') else line

def makeLowerCase(line: str) -> str:
	return line.lower()

def normalize(line: str) -> str:
	line = removeTrailingDot(line)
	line = makeLowerCase(line)
	return line

def downloadSource(session: requests.Session, source) -> List[str]:
	response = session.get(source.url)
	if response.status_code != 200:
		raise DownloadError(source, response.status_code)
	return response.text.splitlines()

def downloadSources(sources) -> List[str]:
	""" downloads lists of domain names from the sources, then normalizes and validates them """
	if len(sources) == 0:
		raise NoSourcesConfiguredError()
	lines: List[str] = []
	with requests.Session() as session:
		printError("begin downloading from {} {}".format(len(sources), "source" if len(sources) == 1 else "sources"))
		for source in sources:
			downloadedLines = downloadSource(session, source)
			normalizedLines = map(normalize, downloadedLines)
			wantedLines = filter(isValid, normalizedLines)
			formattedLines = list(source.format(wantedLines))
			lines.extend(formattedLines)
			printError(createSourceDownloadSummary(source, len(formattedLines)))
	return lines

def createSourceDownloadSummary(source, count) -> str:
	longestNameLength = max(len(s.name) for s in getSources())
	paddingRequired = longestNameLength - len(source.name)
	padding = " " * paddingRequired # creates a string of empty spaces of paddingRequired's length
	return "-\t{}{}\t{}".format(source.name, padding, count)

def sourceToString(source) -> str:
	return "{} ({})".format(source.name, source.url)

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
		for line in lines:
			if line.__contains__("localhost"):
				continue
			line = str.replace(line, "0.0.0.0 ", "")
			line = line.partition("#")[0] # removes trailing comment if present
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		formatted = []
		for line in lines:
			line = str.replace(line, "0.0.0.0", "")
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

class FirebogEasyList():
	def __init__(self) -> None:
		self._name = "Firebog Easy List"
		self._url = "https://v.firebog.net/hosts/Easylist.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

class OSIntDigitalSide():
	def __init__(self) -> None:
		self._name = "OSIntDigitalSide"
		self._url = "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

class PolishFiltersTeamKADHosts():
	def __init__(self) -> None:
		self._name = "Polish Filters Team KAD Hosts"
		self._url = "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			line = str.replace(line, "0.0.0.0 ", "")
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

class PhishingArmyBlocklistExtended():
	def __init__(self) -> None:
		self._name = "Phishing Army Blocklist Extended"
		self._url = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
	@property
	def name(self):
		return self._name
	@property
	def url(self):
		return self._url
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return sourceToString(self.name, self.url)

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

class UnboundFormatter:
	def __init__(self) -> None:
		self._name = "Unbound Formatter"
	@property
	def name(self):
		return self._name
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = 'local-zone: "{}." always_nxdomain'.format(line)
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return self.name

class BindFormatter:
	def __init__(self) -> None:
		self._name = "BIND Formatter"
	@property
	def name(self):
		return self._name
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = 'zone "{}" {{ type master; file "/etc/bind/zones/db.poison"; }};'.format(line)
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return self.name

class WindowsHostsFileFormatter:
	def __init__(self) -> None:
		self._name = "Windows Hosts File Formatter"
	@property
	def name(self):
		return self._name
	def format(self, lines: List[str]) -> List[str]:
		formatted = ["127.0.0.1 localhost", "::1 localhost", ""]
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = "0.0.0.0 {}".format(line)
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return self.name

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
		filterFunc = lambda x: not x.startswith("#") and len(x) > 0
		return list(filter(filterFunc, file.read().splitlines()))

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
