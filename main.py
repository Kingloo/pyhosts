import os
import sys
from formatters import BindFormatter, UnboundFormatter, WindowsHostsFileFormatter
from exceptions import UnknownServerTypeException, UsageException

def DetermineServerType(serverArg):
	serverArgLower = serverArg.lower()
	if serverArgLower == "unbound":
		return UnboundFormatter()
	elif serverArgLower == "bind":
		return BindFormatter()
	elif serverArgLower == "winhosts":
		return WindowsHostsFileFormatter()
	else:
		raise UnknownServerTypeException(serverArg)

def process(serverType, filename):
	print("using {} and saving to {}".format(str(serverType), filename))

def ParseArguments(args):
	if len(args) < 1:
		raise UsageException("too few arguments")
	serverType = DetermineServerType(args[0])
	if len(args) >= 2:
		if os.path.exists(args[1]):
			raise FileExistsError(args[1])
		filename = args[1]
	else:
		filename = None
	return (serverType, filename)

def main(args):
	try:
		(serverType, filename) = ParseArguments(args)
		process(serverType, filename)
	except Exception as e:
		print(str(e))

if __name__ == "__main__":
	main(sys.argv[1:])

# first argument is filename (removed)
# second argument is DNS server type (required)
# third argument is filename to save to (optional)
