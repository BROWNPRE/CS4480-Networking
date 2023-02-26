# Place your imports here
import signal
import threading
import time
import sys
from optparse import OptionParser
from socket import *
from urllib.parse import urlparse

cache = dict()
cacheEnabled = False
blocklist = list()
blocklistEnabled = False

lock = threading.Lock()

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)

# Checks the cache
def check_cache(hostname, port, path):
    global cache
    global cacheEnabled
    global blocklist
    global blocklistEnabled
    if not cacheEnabled:
        return None

    key = (hostname, port, path)
    response = None
    with lock:
        response = cache.get(key)
    return response

# Checks the blocklist
def check_blocklist(host):
    global cache
    global cacheEnabled
    global blocklist
    global blocklistEnabled
    if not blocklistEnabled:
        return False
    # Locks the list and creates a copy
    listCopy = list()
    with lock:
        for blocked in blocklist:
            if blocked in host:
                return True
    return False

# Reformats the request and contacts the origin server
def contact_origin_server(splitRequest, headers):
    global cache
    global cacheEnabled
    global blocklist
    global blocklistEnabled
    # Get the full URL portion of the request
    fullURL = splitRequest[1]

    # Seperate portions of the URL and ensure it has a proper URI
    if 'http://' not in fullURL:
        #fullURL = 'http://' + fullURL
        return 'HTTP/1.0 400 Bad Request\r\n'
    parsedURL = urlparse(fullURL)
    hostname = parsedURL.hostname
    port = parsedURL.port
    path = parsedURL.path
    if port == None:
        port = 80
    if path == '':
        #path = '/'
        return 'HTTP/1.0 400 Bad Request\r\n'
    if hostname == None or hostname == '':
        return 'HTTP/1.0 400 Bad Request\r\n'

    # Check blocklist
    if check_blocklist(hostname):
        return 'HTTP/1.0 403 Forbidden\r\n'

    # Check the cache
    res = check_cache(hostname, port, path)


    # Create a new socket to talk to the remote server
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # Send required headers
    clientSocket.connect((hostname, port))
    getMsg = 'GET ' + path + ' HTTP/1.0\r\n'
    clientSocket.send(getMsg.encode())
    hostMsg = 'Host: ' + hostname + '\r\n'
    clientSocket.send(hostMsg.encode())
    connMsg = 'Connection: close\r\n'
    # Send additional client headers
    clientSocket.send(connMsg.encode())
    for header in headers:
        if header == 'Host' or header == 'Connection':
            continue
        newMsg = header + ': ' + headers[header] + '\r\n'
        clientSocket.send(newMsg.encode())
    # Add If-modified-since
    if res is not None:
        lastMod = 'If-Modified-Since: ' + res[0] + '\r\n'
        clientSocket.send(lastMod.encode())
    # End with a double newline
    clientSocket.send('\r\n'.encode())

    # Read the response
    response = ''
    response += clientSocket.recv(1024).decode()
    # If the response is larger than 1024
    additionalSize = 0
    for block in response.split('\r\n'):
        if 'Content-Length' in block:
            length = int(block.split(':')[1].replace(' ', ''))
            if length > 1024:
                additionalSize = length
            continue
    if additionalSize > 0:
        response += clientSocket.recv(additionalSize).decode()

    clientSocket.close()
    # If it has not been cached add it to cache if necessary
    if res is None:
        # Update cache
        if cacheEnabled and '200 OK' in response:
            lastModified = ''
            for line in response.split('\r\n'):
                if 'Last-Modified:' in line:
                    lastModified = line.replace('Last-Modified: ', '')
            with lock:
                cache[(hostname, port, path)] = (lastModified, response)
        return response

    # If it has been cached check for updates
    if '200 OK' in response:
        lastModified = ''
        for line in response.split('\r\n'):
            if 'Last-Modified:' in line:
                lastModified = line.replace('Last-Modified: ', '')
        with lock:
            cache[(hostname, port, path)] = (lastModified, response)
    if '304 Not Modified' in response:
        return res[1]
    return response


def give_to_thread(connectionSocket, addr):
    global cache
    global cacheEnabled
    global blocklist
    global blocklistEnabled
    request = connectionSocket.recv(1024).decode()
    # Keep reading until you get a double newline
    while '\r\n\r\n' not in request:
        request += connectionSocket.recv(1024).decode()
    # Separate headers
    split = request.split('\r\n')
    # Separate the parts of the request line
    splitRequest = split[0].split(' ')
    split[0] = ''
    headers = dict()
    # Check for a bad request (more checks later) and non-GET methods
    notGet = False
    badRequest = False
    if len(splitRequest) == 0:
        badRequest = True
    if splitRequest[0] != 'GET':
        if splitRequest[0] == 'HEAD' or splitRequest[0] == 'POST':
            notGet = True
        else:
            badRequest = True
    if len(splitRequest) != 3 or splitRequest[2] != 'HTTP/1.0':
        badRequest = True

    # Read all additional headers
    for req in split:
        if len(req) < 1:
            continue
        sRequest = req.replace('\r\n', '').split(': ', 2)
        if len(sRequest) != 2 or ' ' in sRequest[0]:
            badRequest = True
            break
        headers[sRequest[0]] = sRequest[1]

    # Handle blocklist/cache requests
    parsedURL = urlparse(splitRequest[1])
    isProxyRequest = False
    path = parsedURL.path
    if path == '/proxy/cache/enable':
        cacheEnabled = True
        isProxyRequest = True
    if path == '/proxy/cache/disable':
        cacheEnabled = False
        isProxyRequest = True
    if path == '/proxy/cache/flush':
        with lock:
            cache.clear()
        isProxyRequest = True
    if path == '/proxy/blocklist/enable':
        blocklistEnabled = True
        isProxyRequest = True
    if path == '/proxy/blocklist/disable':
        blocklistEnabled = False
        isProxyRequest = True
    if '/proxy/blocklist/add/' in path:
        newpath = path.replace('/proxy/blocklist/add/', '')
        if 'http://' not in newpath:
            newpath = 'http://' + newpath
        parsedPath = urlparse(newpath).hostname
        if parsedPath is None:
            parsedPath = newpath
        with lock:
            blocklist.append(parsedPath)
        isProxyRequest = True
    if '/proxy/blocklist/remove/' in path:
        newpath = path.replace('/proxy/blocklist/remove/', '')
        with lock:
            blocklist.remove(newpath)
        isProxyRequest = True
    if path == '/proxy/blocklist/flush':
        with lock:
            blocklist.clear()
        isProxyRequest = True

    if isProxyRequest:
        connectionSocket.send('HTTP/1.0 200 OK\r\n'.encode())
        connectionSocket.close()
        return

    # Send a response
    response = ''
    if badRequest:
        response = 'HTTP/1.0 400 Bad Request\r\n'
    if notGet:
        response = 'HTTP/1.0 501 Not Implemented\r\n'
    if not badRequest and not notGet:
        response = contact_origin_server(splitRequest, headers)  # + '\r\n'

    # Send response and close client's socket
    connectionSocket.send(response.encode())
    connectionSocket.close()



# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# Create the server socket
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', port))
serverSocket.listen(1)

while True:
    # Setup server socket
    connectionSocket, addr = serverSocket.accept()
    thread = threading.Thread(target=give_to_thread, args=(connectionSocket, addr), daemon=True)
    thread.start()