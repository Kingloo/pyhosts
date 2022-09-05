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
		FirebogEasyPrivacy(),
		FirebogEasyList(),
		OSIntDigitalSide(),
		PolishFiltersTeamKADHosts(),
		PhishingArmyBlocklistExtended()
	]

def isValid(line: str) -> bool:
	isComment = line.startswith('#')
	isEmpty = len(line) == 0
	isLocalhost = line == "localhost"
	return isComment == False and isEmpty == False and isLocalhost == False

def removeTrailingDot(line: str) -> str:
	return line[:-1] if line.endswith('.') else line

def downloadSource(session: requests.Session, source) -> List[str]:
	response = session.get(source.url)
	if response.status_code != 200:
		raise DownloadError(source, response.status_code)
	return response.text.splitlines()

def downloadSources(sources) -> List[str]:
	if len(sources) == 0:
		raise NoSourcesConfiguredError()
	lines: List[str] = []
	with requests.Session() as session:
		printError("begin downloading from {} {}".format(len(sources), "source" if len(sources) == 1 else "sources"))
		for source in sources:
			downloadedLines = downloadSource(session, source)
			linesWithoutTrailingDot = map(removeTrailingDot, downloadedLines)
			wantedLines = filter(isValid, linesWithoutTrailingDot)
			formattedLines = source.format(wantedLines)
			lines.extend(formattedLines)
			printError(createSourceDownloadSummary(source, len(lines)))
	printError("finished downloading ({} total)".format(len(lines)))
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
