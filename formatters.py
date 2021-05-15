class UnboundFormatter:
	def __init__(self) -> None:
		self.list = []
	def __str__(self) -> str:
		return "Unbound Formatter"

class BindFormatter:
	def __init__(self) -> None:
		self.list = []
	def __str__(self) -> str:
		return "BIND Formatter"

class WindowsHostsFileFormatter:
	def __init__(self) -> None:
		self.list = []
	def __str__(self) -> str:
		return "Windows Hosts File Formatter"

