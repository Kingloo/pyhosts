import requests
from typing import List
from main import printError
from exceptions import DownloadError, NoSourcesConfiguredError

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
	return lines

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
