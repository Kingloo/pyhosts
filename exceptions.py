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
