import requests
import sys
import json
import csv
import os
import re
import time
from prettytable import PrettyTable
from tqdm import trange, tqdm
from getpass import getpass
import netmiko
import textfsm
from colorama import Fore
# test
# Open the FSM templates
controlConns = open("conns.txt")
bfdSessions = open("bfd.txt")
omp_tlocs = open("omp.txt")
outfile_name = open("outfile.csv", "w+")
outfile = outfile_name

if 'InsecureRequestWarning' in dir(requests.packages.urllib3.exceptions):
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Cross-platform colored terminal text.
color_bars = [Fore.BLACK,
    Fore.RED,
    Fore.GREEN,
    Fore.YELLOW,
    Fore.BLUE,
    Fore.MAGENTA,
    Fore.CYAN,
    Fore.WHITE]

##############################################################################################
##                                                                                          ##
##                     SSH CONNECT FUNCTION FOR COLLECTING DEVICE STATS                     ##
##                                                                                          ##
##############################################################################################
def make_connection(ip, username, password):
    return netmiko.ConnectHandler(device_type='cisco_xr', ip=ip, username=username, password=password)

def colourPrint(message,type):
    if type == "HEADER":
        print(bcolors.HEADER+message+ bcolors.ENDC)
    elif type == "OKBLUE":
        print(bcolors.OKBLUE + message + bcolors.ENDC)
    elif type == "OKGREEN":
        print(bcolors.OKGREEN + message + bcolors.ENDC)
    elif type == "WARNING":
        print(bcolors.WARNING + message + bcolors.ENDC)
    elif type == "FAIL":
        print(bcolors.FAIL + message + bcolors.ENDC)
    elif type == "BOLD":
        print(bcolors.BOLD + message + bcolors.ENDC)
    elif type == "UNDERLINE":
        print(bcolors.UNDERLINE + message + bcolors.ENDC)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class rest_api_lib:
    def __init__(self, vmanage_ip, vmanage_port, username, password):
        self.vmanage_ip = vmanage_ip
        self.vmanage_port = vmanage_port
        self.session = {}
        self.login(self.vmanage_ip, vmanage_port, username, password)

    ##############################################################################################
    ##                                                                                          ##
    ##                Log in to Viptela RESTFUL API and return session ID                       ##
    ##                                                                                          ##
    ##############################################################################################
    def login(self, vmanage_ip, vmanage_port, username, password):
        base_url = 'https://%s:%s/' % (self.vmanage_ip, vmanage_port)
        login_action = '/j_security_check'

        # Format data for loginForm
        login_data = {'j_username': username, 'j_password': password}
        # URL for posting login data
        login_url = base_url + login_action
        # URL for retrieving client token
        token_url = base_url + 'dataservice/client/token'
        http_session = requests.session()

        # If the vmanage has a certificate signed by a trusted authority change verify to True
        login_response = http_session.post(url=login_url, data=login_data, verify=False)
        if b'<html>' in login_response.content:
            print("Login Failed")
            exit(0)

        # update token to session headers

        login_token = http_session.get(url=token_url, verify=False)
        # print(login_token.content)
        if login_token.status_code == 200:
            if b'<html>' in login_token.content:
                print("Login Token Failed")
                exit(0)

        http_session.headers['X-XSRF-TOKEN'] = login_token.content
        self.session[vmanage_ip] = http_session

    ##############################################################################################
    ##                                                                                          ##
    ##                              RESTFUL API Read                                            ##
    ##                                                                                          ##
    ##############################################################################################
    def getRequest(self, mount_point):
        """GET request"""
        url = "https://%s:%s/%s" % (self.vmanage_ip, self.vmanage_port, mount_point)
        ## print(url)
        response = self.session[self.vmanage_ip].get(url, verify=False)

        data = json.loads(response.content)
        return data

    ##############################################################################################
    ##                                                                                          ##
    ##                                  COLLECT VMANAGE DEVICE TABLE                            ##
    ##                                                                                          ##
    ##############################################################################################
    
    def GetDevices(self):
        api_call = 'dataservice/device'
        # print('api_call:', api_call)
        response = self.getRequest(api_call)
        table = PrettyTable()
        table.field_names = ["device name","system-IP","UUID","Version","Reachability","BFD Sessions","Control Connections","Management Address"]
        conns_table = PrettyTable()
        conns_table.field_names = ["Mgmt IP","Peer Type","Peer System IP","Site ID","Peer Private IP","Peer Public IP","Local Colour","Proxy","State","Uptime"]
        bfd_table = PrettyTable()
        bfd_table.field_names = ["Mgmt IP","System IP","Site ID","BFD State","Source TLOC Colour","Remote TLOC Colour","Source IP","DST Public IP","Encap","Multiplier","Uptime","Transitions"]
        omp_table = PrettyTable()
        omp_table.field_names = ["Mgmt IP","TLOC IP","Colour","Encap","From Peer","Status","Key","Public IP","Private IP","BFD Status"]
        #omp_table.field_names = ["Mgmt IP","TLOC IP"]
        for device in (response['data']):
            if device['device-type'] == 'vedge':       
                vedge = device['local-system-ip']
                interfaceURL = 'dataservice/device/interface?deviceId=%s&vpn-id=512&&'%(vedge)
                interfaceData = self.getRequest(interfaceURL)          
                ip = interfaceData['data'][0]['ip-address']
                ip = ip.split('/')
                ip = ip[0]
                table.add_row([device['host-name'], device['local-system-ip'], device['uuid'], device['version'], device['reachability'],device['bfdSessions'],device['controlConnections'],ip])
                
                #
                # Start collecting the data from each discovered vedge
                #
                net_connect = make_connection(ip, sshusername, sshpassword)
                net_connect.send_command('screen-length 1000')

                # Get the Control Connections
                connections = net_connect.send_command('show control connections')
                re_table = textfsm.TextFSM(controlConns)
                con_results = re_table.ParseText(connections)  
                for row in tqdm(con_results,ncols=200, ascii=True, desc="Scanning Control Connections on " + ip):       
                    listobj = [str(ip)]
                    for s in row:
                        if s:
                            listobj.append(s)
                    conns_table.add_row(listobj)
                conns_table.add_row(['-','-','-','-','-','-','-','-','-','-'])   
                
                # Get the BFD Sessions
                bfd_sessions = net_connect.send_command('show bfd sessions')
                re_table = textfsm.TextFSM(bfdSessions)
                bfd_results = re_table.ParseText(bfd_sessions)  
                for row in tqdm(bfd_results,ncols=200, ascii=True, desc="Scanning BFD Sessions on " + ip):       
                    listobj = [str(ip)]
                    for s in row:
                        if s:
                            listobj.append(s)
                    bfd_table.add_row(listobj)
                bfd_table.add_row(['-','-','-','-','-','-','-','-','-','-','-','-'])
                # Get the OMP TLOC's
                omp_command = net_connect.send_command_timing('show omp tlocs | beg ipv4 | tab')
                re_table = textfsm.TextFSM(omp_tlocs)
                omp_results = re_table.ParseText(omp_command)  
                for row in tqdm(omp_results,ncols=200, ascii=True, desc="Scanning OMP TLOC Paths on " + ip):       
                    listobj = [str(ip)]
                    for s in row:
                        if s:
                           listobj.append(s)
                    omp_table.add_row(listobj)
                omp_table.add_row(['-','-','-','-','-','-','-','-','-','-'])
                net_connect.disconnect()

               
            else:
                table.add_row([device['host-name'], device['local-system-ip'], device['uuid'], device['version'], device['reachability'],"N/A",device['controlConnections'],"N/A"])
        print("\nSDWAN Fabric Device Information")
        print(table)
        print("\nControl Connections on all Routers")
        print(conns_table)
        print("\nBFD Sessions on all Routers")
        print(bfd_table)
        print("\nTLOC Paths on all Routers")
        print(omp_table)

    ##############################################################################################
    ##                                                                                          ##
    ##                     SSH CONNECT FUNCTION FOR COLLECTING DEVICE STATS                     ##
    ##                                                                                          ##
    ##############################################################################################
    def make_connection (ip, username, password):
        return netmiko.ConnectHandler(device_type='cisco_ios', ip=ip, username=username, password=password)


sshusername = 'admin'
sshpassword = 'admin'

def main():
    vmanage_ip = "192.168.30.85"
    vmanage_port = "8443"
    username = "admin"
    password = "admin"
    obj = rest_api_lib(vmanage_ip, vmanage_port, username, password)

    print("\nLogging into vManage as user: "+username)
    print("Collection job running on all devices in SDWAN fabric ....")
    obj = rest_api_lib(vmanage_ip, vmanage_port, username, password)
    obj.GetDevices()

if __name__ == "__main__":
    main()


