#!/usr/bin/python3

from pexpect import pxssh
from threading import Thread
import getpass
import json
import queue
import os


class ScanThread(Thread):

    def __init__(self, hostname, domain, credentials, queue):
        Thread.__init__(self)
        self.hostname = hostname
        self.domain = domain
        self.credentials = credentials
        self.queue = queue

    def run(self):
        s = pxssh.pxssh()
        try:
            s.login(self.hostname+"."+self.domain, self.credentials[0], self.credentials[1], login_timeout=5)
            s.logout()
            self.queue.put((self.hostname, True))
        except pxssh.ExceptionPxssh:
            self.queue.put((self.hostname, False))


def init():
    username = str(input("Username : "))
    password = getpass.getpass("Password : ")
    return username, password


def scan(host_list, domain, credentials):
    thread_pool = []
    q = queue.Queue()
    for hostname in host_list:
        thread = ScanThread(hostname, domain, credentials, q)
        thread_pool.append(thread)
        thread.start()
    for thread in thread_pool:
        buf = q.get()
        host_list[buf[0]] = buf[1]
        thread.join()


def get_valid_server(host_list):
    for host in host_list:
        if host_list[host] :
            return host
    return None


def connect(hostname, domain, credentials):
    s = pxssh.pxssh()
    try:
        s.login(hostname + "." + domain, credentials[0], credentials[1], login_timeout=5)
        cmd = str(input(credentials[0] + "@" + hostname + " > "))
        while(cmd != "exit"):
            s.sendline(cmd)
            s.prompt()
            print(s.before.decode())
            cmd = str(input(credentials[0] + "@" + hostname + " > "))
        s.logout()
    except pxssh.ExceptionPxssh:
        print("Unable to connect to " + hostname + "." + domain)

if __name__ == '__main__':
    with open('hosts.json') as hosts_f:
        hostList = json.load(hosts_f)
    with open('config.json') as conf_f:
        config = json.load(conf_f)
    os.system("clear")
    print("Welcome to pyUlbTools")
    if config["username"] == "" or config["password"] == "":
        credentials = init()
    else:
        credentials = (config["username"], config["password"])
    choice = ""
    print("Building the network map, please wait...")
    scan(hostList, config["domain"], credentials)
    print("Ready!")
    while choice != "exit":
        choice = str(input("pyUlbTools > "))
        if choice == "uplist":
            print("List of reachable machines")
            for host in hostList:
                if hostList[host]:
                    print(host + " is up")
        elif choice[:7] == "connect":
            arguments = choice[7:].strip()
            if arguments != "":
                if arguments in hostList:
                    if hostList[arguments]:
                        connect(arguments, config["domain"], credentials)
                    else:
                        print(arguments + " server not reachable, uplist for more details")
                else:
                    print(arguments + " not in the server list, uplist for more details")
            else:
                connect(get_valid_server(hostList), config["domain"], credentials)
        elif choice == "sync":
            print("Synchronizing...")
            os.system("xterm -e 'rsync -arvh --delete --backup --backup-dir=" + config["backup_dir"] + credentials[0] + " " + credentials[0] + "@" + get_valid_server(hostList) + "." + config["domain"] + ":/home/$USER/ " + config["sync_dir"] + credentials[0] + "'")
        elif choice == "help" or choice == "h":
            print("uplist : list all server up\nconnect : connect to a server\nsync : synchronize distant session\nhelp : open this help\nexit : close pyUlbTools")
