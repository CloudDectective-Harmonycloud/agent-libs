from builtins import object
import netifaces

class Network(object):

    def __init__(self):
        self.addresses = set()
        self.dockerIfaces = {}
        self.interfaces = netifaces.interfaces()
        self.addresses.add('127.0.1.1')
        #collect all the hosts ip addresses
        for interface in self.interfaces:
            try:
                self.addresses.add(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'])
            except KeyError:
                pass

    def ipIsLocalHost(self, ip):
        return ip in self.addresses

    def isADockerContainerIp(self, ip):
        # this need to be more robust using the docker module
        return ip[0:len('172.17')] == '172.17'

    def ipIsLocalHostOrDockerContainer(self, ipAddress):
        return self.ipIsLocalHost(ipAddress) or self.isADockerContainerIp(ipAddress)

    def _getAllDockerContainersIp(self):
        pass


