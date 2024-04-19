class UnknownServerTypeError(Exception):
	"""Raised when the (REQUIRED) DNS server type is not recognised/supported by pyhosts"""

	def __init__(self, unknownServerType) -> None:
		self._unknownServerType = unknownServerType
		super().__init__(self.unknownServerType)

	@property
	def unknownServerType(self):
		return self._unknownServerType

	def __str__(self) -> str:
		return self.message


class UsageError(Exception):
	"""Raised when the command line arguments don't match required usage"""

	def __init__(self, message) -> None:
		self._message = message
		super().__init__(self.message)

	@property
	def message(self):
		return self._message

	def __str__(self) -> str:
		return self.message


class DownloadError(Exception):
	"""Raised when downloading a source return an HTTP status code other than 200"""

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
	"""Raised when there are no sources configured"""

	def __init__(self) -> None:
		self._message = "there are no sources configured"
		super().__init__(self.message)

	@property
	def message(self):
		return self._message

	def __str__(self) -> str:
		return self.message


class FileWriteError(Exception):
	"""Raised when the output file could not be written to"""

	def __init__(self, filename) -> None:
		self._message = "file could not be written to: {}".format(filename)
		super().__init__(self.message)

	@property
	def message(self):
		return self._message

	def __str__(self) -> str:
		return self.message


class FileReadError(Exception):
	"""Raised when file could not be read"""

	def __init__(self, filename) -> None:
		self._message = "file could not be read: {}".format(filename)
		super().__init__(self.message)

	@property
	def message(self):
		return self._message

	def __str__(self) -> str:
		return self.message


class LocalhostFoundError(Exception):
	"""Raised when localhost found its way to a formatter"""

	def __init__(self) -> None:
		self._message = "tried to pass localhost to a formatter"
		super().__init__(self.message)

	@property
	def message(self):
		return self._message

	def __str__(self) -> str:
		return self.message
