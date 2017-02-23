#!/usr/bin/python3

from pexpect import pxssh
from threading import Thread
import getpass
import json
import queue
import os


class ScanThread(Thread):

    def __init__(self, hostname, domain, username, password, queue):
        Thread.__init__(self)
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.queue = queue

    def run(self):
        s = pxssh.pxssh()
        try:
            s.login(self.hostname+"."+self.domain, self.username, self.password, login_timeout=5)
            s.logout()
            self.queue.put((self.hostname, True))
        except pxssh.ExceptionPxssh:
            self.queue.put((self.hostname, False))


class CmdThread(Thread):

    def __init__(self, hostname, domain, username, password, cmd, queue):
        Thread.__init__(self)
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.cmd = cmd
        self.queue = queue

    def run(self):
        s = pxssh.pxssh()
        try:
            s.login(self.hostname+"."+self.domain, self.username, self.password, login_timeout=5)
            s.sendline(self.cmd)
            s.prompt()
            self.queue.put((self.hostname, s.before.decode()))
            s.logout()
        except pxssh.ExceptionPxssh:
            self.queue.put((self.hostname, "Error while executing the command " + self.cmd + " on " + self.hostname))


def scan(host_list, domain, username, password):
    thread_pool = []
    q = queue.Queue()
    for hostname in host_list:
        thread = ScanThread(hostname, domain, username, password, q)
        thread_pool.append(thread)
        thread.start()
    for thread in thread_pool:
        buf = q.get()
        host_list[buf[0]] = buf[1]
        thread.join()


def set_credentials():
    username = str(input("Username : "))
    password = getpass.getpass("Password : ")
    return username, password


def mass_cmd(host_list, domain, username, password, cmd):
    thread_pool = []
    q = queue.Queue()
    for hostname in host_list:
        if host_list[hostname]:
            thread = CmdThread(hostname, domain, username, password, cmd, q)
            thread_pool.append(thread)
            thread.start()
    for thread in thread_pool:
        buf = q.get()
        print("-------------------------------------------------- " + buf[0] + " :\n" + buf[1])
        thread.join()


def get_valid_server(host_list):
    for host in host_list:
        if host_list[host] :
            return host
    return None


def connect(hostname, domain, username, password):
    s = pxssh.pxssh()
    try:
        s.login(hostname + "." + domain, username, password, login_timeout=5)
        cmd = str(input(username + "@" + hostname + " > "))
        while cmd != "exit":
            s.sendline(cmd)
            s.prompt()
            print(s.before.decode())
            cmd = str(input(username + "@" + hostname + " > "))
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
        config["username"], config["password"] = set_credentials()
    choice = ""
    print("Building the network map, please wait...")
    scan(hostList, config["domain"], config["username"], config["password"])
    print("Ready!")
    while choice != "exit":
        choice = str(input("pyUlbTools > "))
        if choice == "uplist":
            print("List of reachable machines")
            for host in hostList:
                if hostList[host]:
                    print(host + " is up")
        elif choice == "downlist":
            print("List of unreachable machines")
            for host in hostList:
                if not(hostList[host]):
                    print(host + " is down")
        elif choice == "user":
            print("Currently using " + config["username"] + " user")
        elif choice == "chguser":
            print("Enter new username and password")
            config["username"], config["password"] = set_credentials()
            print("Successfully changed")
        elif choice[:7] == "connect":
            arguments = choice[7:].strip()
            if arguments != "":
                if arguments in hostList:
                    if hostList[arguments]:
                        connect(arguments, config["domain"], config["username"], config["password"])
                    else:
                        print(arguments + " server not reachable, uplist for more details")
                else:
                    print(arguments + " not in the server list, uplist for more details")
            else:
                connect(get_valid_server(hostList), config["domain"], config["username"], config["password"])
        elif choice[:4] == "mcmd":
            cmd = choice[4:].strip()
            if cmd != "":
                mass_cmd(hostList, config["domain"], config["username"], config["password"], cmd)
            else:
                print("no command specified")
        elif choice == "sync":
            print("Synchronizing...")
            os.system("xterm -e 'rsync -arvh --delete --backup --backup-dir=" + config["backup_dir"] + config["username"] + " " + config["username"] + "@" + get_valid_server(hostList) + "." + config["domain"] + ":/home/$USER/ " + config["sync_dir"] + config["username"] + "'")
        elif choice == "help" or choice == "h":
            print("uplist : list all server up\ndownlist : list all server down\nuser : show user currently used\nchguser : change user\nconnect : connect to a server\nmcmd : execute a command on every computer reachable\nsync : synchronize distant session\nhelp : open this help\nexit : close pyUlbTools")
