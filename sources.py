from typing import List

class MVPS():
	def __init__(self) -> None:
		self.name = "MVPS"
		self.url = "http://winhelp2002.mvps.org/hosts.txt"
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			isComment = line.startswith("#")
			isEmpty = len(line) == 0
			containsLocalhost = line.__contains__("localhost")
			isValid = isComment == False and isEmpty == False and containsLocalhost == False
			if isValid:
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
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentAds():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Ads"
		self.url = "https://v.firebog.net/hosts/Prigent-Ads.txt"
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentCrypto():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Crypto"
		self.url = "https://v.firebog.net/hosts/Prigent-Crypto.txt"
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogPrigentMalware():
	def __init__(self) -> None:
		self.name = "Firebog Prigent Malware"
		self.url = "https://v.firebog.net/hosts/Prigent-Malware.txt"
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogAdmiral():
	def __init__(self) -> None:
		self.name = "Firebog Admiral"
		self.url = "https://v.firebog.net/hosts/Admiral.txt"
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)

class FirebogEasyPrivacy():
	def __init__(self) -> None:
		self.name = "Firebog Easy Privacy"
		self.url = "https://v.firebog.net/hosts/Easyprivacy.txt"
	def format(self, lines: List[str]) -> List[str]:
		return lines
	def __str__(self) -> str:
		return "{} ({})".format(self.name, self.url)
