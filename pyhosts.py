import os
import sys
import logging
import requests
from typing import List

class UnknownServerTypeError(Exception):
	""" Raised when the (REQUIRED) DNS server type is not recognised/supported by pyhosts """
	def __init__(self, unknownServerType) -> None:
		self.unknownServerType = unknownServerType
		super().__init__(self.unknownServerType)
	def __str__(self) -> str:
		return self.message

class UsageError(Exception):
	""" Raised when the command line arguments don't match required usage """
	def __init__(self, message) -> None:
		self.message = message
		super().__init__(self.message)
	def __str__(self) -> str:
		return self.message

class DownloadError(Exception):
	""" Raised when downloading a source return an HTTP status code other than 200 """
	def __init__(self, source, status_code) -> None:
		self.source = source
		self.status_code = status_code
		self.message = "{} ({})".format(source, status_code)
		super().__init__(self.message)
	def __str__(self) -> str:
		return self.message

class NoSourcesConfiguredError(Exception):
	""" Raised when there are no sources configured """
	def __init__(self) -> None:
		self.message = "there are no sources configured"
		super().__init__(self.message)
	def __str__(self) -> str:
		return self.message

class FileWritingError(Exception):
	""" Raised when the output file could not be written to """
	def __init__(self, filename) -> None:
		self.message = "file could not be written to: {}".format(filename)
		super().__init__(self.message)
	def __str__(self) -> str:
		return self.message

class LocalhostFoundError(Exception):
	""" Raised when localhost found its way to a formatter """
	def __init__(self) -> None:
		self.message = "tried to pass localhost to a formatter"
		super().__init__(self.message)
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
		self.name = "MVPS"
		self.url = "http://winhelp2002.mvps.org/hosts.txt"
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
		self.name = "Firebog AdGuard DNS"
		self.url = "https://v.firebog.net/hosts/AdguardDNS.txt"
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentAds():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Ads"
		self.url = "https://v.firebog.net/hosts/Prigent-Ads.txt"
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentCrypto():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Crypto"
		self.url = "https://v.firebog.net/hosts/Prigent-Crypto.txt"
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentMalware():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Malware"
		self.url = "https://v.firebog.net/hosts/Prigent-Malware.txt"
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogAdmiral():
	def __init__(self) -> None:
		self.name = "Firebog Admiral"
		self.url = "https://v.firebog.net/hosts/Admiral.txt"
	def format(self, lines: List[str]) -> List[str]:
		return excludeUnwantedLines(lines)
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogEasyPrivacy():
	def __init__(self) -> None:
		self.name = "Firebog Easy Privacy"
		self.url = "https://v.firebog.net/hosts/Easyprivacy.txt"
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
		printError("finished downloading")
	return list(set(lines)) # removes duplicates

def writeLinesToStdOut(lines):
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
	try:
		lines = downloadSources(getSources())
		printError("downloaded {} distinct domains".format(len(lines)))
	except DownloadError as e:
		printError("downloading failed ({})".format(e.message))
		sys.exit(-1)
	formattedForServer = serverFormatter.format(lines)
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
		print(getUsage())
		print("-----------------")
		logging.getLogger(__name__).exception(e)
		sys.exit(-1)

if __name__ == "__main__":
	main(sys.argv[1:])
