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

class BaseFormatter():
	@property
	def name(self):
		return self._name
	def __str__(self) -> str:
		return self.name

class UnboundFormatter(BaseFormatter):
	def __init__(self) -> None:
		self._name = "Unbound Formatter"
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = 'local-zone: "{}." always_nxdomain'.format(line)
			formatted.append(line)
		return formatted

class BindFormatter(BaseFormatter):
	def __init__(self) -> None:
		self._name = "BIND Formatter"
	def format(self, lines: List[str]) -> List[str]:
		formatted = []
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = 'zone "{}" {{ type master; file "/etc/bind/zones/db.poison"; }};'.format(line)
			formatted.append(line)
		return formatted

class WindowsHostsFileFormatter(BaseFormatter):
	def __init__(self) -> None:
		self._name = "Windows Hosts File Formatter"
	def format(self, lines: List[str]) -> List[str]:
		formatted = ["127.0.0.1 localhost", "::1 localhost", ""]
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = "0.0.0.0 {}".format(line)
			formatted.append(line)
		return formatted
