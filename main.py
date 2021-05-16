import os
import sys
import logging
import requests
from formatters import *
from sources import *
from exceptions import *

sources = [
	MVPS(),
	FirebogAdGuardDNS(),
	FirebogPrigentAds(),
	FirebogPrigentMalware(),
	FirebogPrigentCrypto(),
	FirebogAdmiral(),
	FirebogEasyPrivacy()
]

def downloadSource(session: requests.Session, source) -> List[str]:
	response = session.get(source.url)
	if response.status_code is not 200:
		raise DownloadError(source, response.status_code)
	return response.text.splitlines()

def createSourceDownloadSummary(source, count):
	longestNameLength = max(len(s.name) for s in sources)
	paddingRequired = longestNameLength - len(source.name)
	padding = " " * paddingRequired
	return "-\t{}{}\t{}".format(source.name, padding, count)

def downloadSources(sources) -> List[str]:
	if len(sources) == 0:
		raise NoSourcesConfiguredError()
	lines = []
	with requests.Session() as session:
		for source in sources:
			downloadedLines = downloadSource(session, source)
			formattedLines = source.format(downloadedLines)
			for line in formattedLines:
				lines.append(line)
			# printError("\t{}\t\t\t{} domains downloaded".format(source.name, len(formattedLines)))
			printError(createSourceDownloadSummary(source, len(formattedLines)))

	return list(set(lines)) # removes duplicates

def writeLinesToStdOut(lines):
	print("\n".join(lines), file=sys.stdout)

def writeLinesToFile(lines, filename):
	if len(lines) > 0:
		with open(filename, "w") as file:
			if file.writable:
				file.write("\n".join(lines))
			else:
				raise FileWritingError(filename)
	else:
		printError("no lines to write")

def writeLines(lines, filename):
	if filename is None:
		writeLinesToStdOut(lines)
	else:
		writeLinesToFile(lines, filename)

def process(serverFormatter, filename):
	printError("using {} and saving to {}".format(str(serverFormatter), filename))
	lines: List[str] = []
	try:
		lines = downloadSources(sources)
		printError("downloaded {} distinct domains".format(len(lines)))
	except DownloadError as e:
		sys.exit("download failed ({}), exiting".format(e.message))
	# formattedForServer = serverFormatter.format(lines)
	# writeLines(formattedForServer, filename)
	writeLines(lines, filename)

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

def parseArguments(args):
	if len(args) < 1:
		raise UsageError("too few arguments")
	serverFormatter = determineServerFormatter(args[0])
	if len(args) >= 2:
		if os.path.exists(args[1]):
			raise FileExistsError(args[1])
		filename = args[1]
	else:
		filename = None
	return (serverFormatter, filename)

def printError(message: str):
	print(message, file=sys.stderr)

def main(args):
	try:
		(serverFormatter, filename) = parseArguments(args)
		process(serverFormatter, filename)
	except Exception as e:
		logging.getLogger(__name__).exception(e)

if __name__ == "__main__":
	main(sys.argv[1:])

# first argument is filename (removed)
# second argument is DNS server type (required)
# third argument is filename to save to (optional)
