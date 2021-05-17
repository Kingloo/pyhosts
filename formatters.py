from typing import List
from exceptions import LocalhostFoundError, UnknownServerTypeError

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

