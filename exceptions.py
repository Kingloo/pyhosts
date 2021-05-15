class UnknownServerTypeException(Exception):
	""" Raised when the (REQUIRED) DNS server type is not recognised/supported by pyhosts """
	def __init__(self, unknownServerType) -> None:
		self.unknownServerType = unknownServerType
		super().__init__(self.unknownServerType)

class UsageException(Exception):
	""" Raised when the command line arguments don't match required usage """
	def __init__(self, message) -> None:
		self.message = message
		super().__init__(self.message)
