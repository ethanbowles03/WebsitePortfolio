import signal
from optparse import OptionParser
import sys
from enum import Enum
from socket import *
from threading import Thread
from urllib.parse import urlparse

class ParseError(Enum):
        '''
        Class used to represent parsing errors, control interface, and blocked website flags
        '''
        NOTIMPL = 1
        BADREQ = 2
        CI = 3
        BLOCKED = 4

class ProxyServer:
    '''
    Class that represents a proxy server. Has the capability to forward, send, and recieve.
    Furthermore, it can block and cache content for the users
    '''
    def __init__(self):
        # Blocklist and Caching Members
        self.cacheflag = False
        self.blocklistflag = False
        self.cache = {}
        self.blocklist = set()

        # Possible http request errors and blocked flag
        self.notimplreq = (ParseError.NOTIMPL, None, None, None, None)
        self.badreq = (ParseError.BADREQ, None, None, None, None)
        self.ci = (ParseError.CI, None, None, None, None)
        self.blocked = (ParseError.BLOCKED, None, None, None, None)

    def ctrl_c_pressed(signal, frame):
        '''
        Signal handler for pressing ctrl-c
        '''
        sys.exit(0)

    def control_interface(self, message : bytes) -> bool:
        '''
        Method that handles the control interface input from the client.
        Changes cache and blocklist features through various get requests

        Args:
            message (bytes): contains the get message sent by client

        Returns:
            bool: flag indicating that an interface command was used
        '''
        if message == b'/proxy/cache/enable':
            self.cacheflag = True
        elif message == b'/proxy/cache/disable':
            self.cacheflag = False
        elif message == b'/proxy/cache/flush':
            self.cache.clear()
        elif message == b'/proxy/blocklist/enable':
            self.blocklistflag = True
        elif message == b'/proxy/blocklist/disable':
            self.blocklistflag = False
        elif message.startswith(b'/proxy/blocklist/add/'):
            self.blocklist.add(message.replace(b'/proxy/blocklist/add/',b''))
        elif message.startswith(b'/proxy/blocklist/remove/'):
            message = message.replace(b'/proxy/blocklist/remove/',b'')
            if message in self.blocklist: self.blocklist.remove(message)
        elif message == b'/proxy/blocklist/flush':
            self.blocklist.clear()
        else:
            return False
        return True
    
    def check_block(self, host: str) -> bool:
        '''
        Checks to see if a host url should be blocked because it is contained in the blockedlist

        Args:
            host (str): the host name and port number to be check against the blocklist

        Returns:
            bool: flag indicating whether illegal block was used
        '''
        if self.blocklistflag == False: return False
        for b in self.blocklist: # Loop through each blocked word and compare
            if b in host:
                return True
        return False
    
    def check_cache(self, parsed: list) -> bool:
        '''
        Checks the state and presence of an object in the cache. 
        First checks whether an object is present in the cache. If it is, build a request with a If-Modified-Since
            and the current date store in the objects cache, and send it to server.
        Parse the server response and update the cache if needs to be updated. 

        Args:
            parsed (list): a list of parsed uri objects, containing the host, port, path, and headers

        Returns:
            bool: flag indicating whether uri has already been cached
        '''
        # Check if in cache
        request = self.build_get_request(parsed[1],parsed[2],parsed[3],parsed[4])
        if request not in self.cache:
            return False

        # Build request with cached date and modified header
        temp=self.cache[request].replace(b"Date:",b"*")
        dt=temp.replace(b"\r\n",b"*").split(b"*")[1]
        request = self.build_get_request(parsed[1],parsed[2],parsed[3],{b'If-Modified-Since': dt})

        # Send request to server and modify cache if 304 not recieved
        with socket(AF_INET, SOCK_STREAM) as s:
            s.connect((parsed[1].decode(), parsed[2]))
            s.sendall(request)
            response = b""
            while True: # Recieve responce from server
                data = s.recv(1024)
                response += data
                if data.endswith(b'\r\n\r\n') or data == b'':
                    break
            
            if b'304' not in response: self.cache[request] = response

        return True


    def parse_request(self, message : bytes):
        """
        Parses a get http request into an Error, host, port, path, and headers

        Args:
            message (bytes): the http get request

        Returns:
            ParseError: if there is an error in the formating return an error and rest null
            bytes: host extracted from the request
            int: port number extracted from the request
            bytes: path extracted from the request
            dict: dictionary containing all the headers extracted from the request

        """
        host, port, path, headers = None, None, None, {}
        # Method checking
        method = message.decode().split()[0]
        if method not in ['POST', 'GET', 'HEAD', 'PUT']: return self.badreq
        if method != 'GET': return self.notimplreq

        # URI Checking
        uri = urlparse(message.decode().split()[1])
        if not uri.scheme or not uri.netloc or not uri.path:
            return self.badreq

        # Header checking
        hs = message.decode().split('\r\n')[1:-2]
        for i in range(len(hs)):
            h = hs[i].split(': ')
            if len(h) != 2 or h[0][-1] == ' ':
                return self.badreq
            headers[h[0].encode()] = h[1].encode()
            
        # Check HTTP Version
        http_version = message.decode().split()
        if len(http_version) < 3 or http_version[2] != 'HTTP/1.0': return self.badreq

        # build return
        url = uri.netloc.split(':')
        host = url[0].encode()
        port = 80 if len(url) == 1 else int(url[1])
        path = uri.path.encode()

        # Checks to see if a control interface command was used, if so return so
        if self.control_interface(path):
            return self.ci

        # Checks to see if a blocked uri was given, if so report
        if self.check_block(host + b':' + str(port).encode()):
            return self.blocked

        # Return valid parsed uri
        return (None, host, port, path, headers)

    def build_get_request(self, host : bytes, port : int, path : bytes, headers : dict) -> bytes: 
        """
        Builds an http get request with the given parameters

        Args:
            host (bytes): host for the request
            port (int): port number to access the host on
            path (bytes): path to travel on the host
            headers (dict): dictionary containing all the headers for the request

        Returns:
            bytes: constructed get http request
        """
        flag = True
        r = b'GET ' + path + b' HTTP/1.0\r\nHost: ' + host + b':' + str(port).encode() + b'\r\n'
        for h in headers:
            if h != b'Connection':
                r += h + b': ' + headers[h] + b'\r\n'
            else:
                flag = False
                r += b'Connection: close\r\n'

        # Always close the connection 
        if flag: r += b'Connection: close\r\n'
        r += b'\r\n' 
        return r

    def handle_client(self, skt : socket, client_addr: str):
        """
        Handles a Client Connection by parsing request, sending to server, and returning
        info to client. This method allows multithreading of clients

        Args:
            skt (socket): socket the client is connected to
            client_address (str): the address of the client
        """
        request = b''
        while True: # Recieve responce from server
            data = skt.recv(1024)
            request += data
            if data.endswith(b'\r\n\r\n') or data == b'':
                break
        parsed = self.parse_request(request)

        # Send error codes if errors found in request, otherwise send request to origin
        if parsed is self.badreq: # Bad Request
            skt.send(b'HTTP/1.0 400 Bad Request\r\n\r\n')
            skt.close()
        elif parsed is self.notimplreq: # Not Implemented Tag
            skt.send(b'HTTP/1.0 501 Not Implemented\r\n\r\n')
            skt.close()
        elif parsed is self.ci: # Command Line Used
            skt.send(b'HTTP/1.0 200 OK\r\n\r\n')
            skt.close()
        elif parsed is self.blocked: # Blocked Website Access
            skt.send(b'HTTP/1.0 403 Forbidden\r\n\r\n')
            skt.close()
        else: # Valid Request
            # Build the request and check if the request has already been cached. If so return cached request
            request = self.build_get_request(parsed[1],parsed[2],parsed[3],parsed[4])
            if self.cacheflag:
                if self.check_cache(parsed):
                    skt.send(self.cache[request])
                    skt.close()
                    return
                
            # Send and await responce from not cached request. Add request to cache
            with socket(AF_INET, SOCK_STREAM) as s: # Send request to origin server
                s.connect((parsed[1].decode(), parsed[2]))
                s.sendall(request)
                response = b""
                while True: # Recieve responce from server
                    data = s.recv(1024)
                    response += data
                    if data.endswith(b'\r\n\r\n') or data == b'':
                        break

                # Send response to client, cache, and close
                if b'404 Not Found' not in response and self.cacheflag: self.cache[request] = response
                skt.send(response)
                skt.close()
            

    def run(self, address: str, port: int):
        '''
        Handles the running of the proxy server. Sets up a listening socket on the specified port and address
        and makes a new TCP connection on a new thread per new client

        Args:
            address (str): server address
            port (int): server port number
        '''
        # Set up signal handling (ctrl-c)
        signal.signal(signal.SIGINT, self.ctrl_c_pressed)

        # Start listening socket binded to give host and port
        with socket(AF_INET, SOCK_STREAM) as listen_skt:
            listen_skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            listen_skt.bind((address, port))
            listen_skt.listen()
            while True: # When client connects, accept, recieve get request, and parse
                skt, client_address = listen_skt.accept()
                Thread(target=self.handle_client, args=(skt, client_address)).start()

# In charge of running the proxy server code. Gets info from CLI and makes new ProxyServer object, which is run.
if __name__ == "__main__":
    # Start of program execution
    # Parse out the command line server address and port number to listen to
    parser = OptionParser()
    parser.add_option('-p', type='int', dest='serverPort')
    parser.add_option('-a', type='string', dest='serverAddress')
    (options, args) = parser.parse_args()

    # Get the port and address from the CLI
    port = options.serverPort
    address = options.serverAddress
    if address is None:
        address = 'localhost'
    if port is None:
        port = 2100
    
    # Run the proxy server on the given port and adress
    server = ProxyServer()
    server.run(address, port)