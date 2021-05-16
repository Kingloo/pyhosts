from typing import List
from exceptions import LocalhostFoundError

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
		formatted = []
		formatted.append("127.0.0.1 localhost")
		formatted.append("::1 localhost")
		formatted.append("")
		for line in lines:
			if line == "localhost":
				raise LocalhostFoundError()
			line = "0.0.0.0 {}".format(line)
			formatted.append(line)
		return formatted
	def __str__(self) -> str:
		return "Windows Hosts File Formatter"

