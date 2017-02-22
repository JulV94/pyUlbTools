#!/usr/bin/python3

from pexpect import pxssh
from threading import Thread
import getpass
import json
import queue
import os

DOMAIN = "ulb.ac.be"


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


def scan(host_list, credentials):
    thread_pool = []
    q = queue.Queue()
    for hostname in host_list:
        thread = ScanThread(hostname, DOMAIN, credentials, q)
        thread_pool.append(thread)
        thread.start()
    for thread in thread_pool:
        buf = q.get()
        host_list[buf[0]] = buf[1]
        thread.join()

if __name__ == '__main__':
    print("Welcome to pyUlbTools")
    with open('hosts.json') as hosts_f:
        hostList = json.load(hosts_f)
    os.system("clear")
    credentials = init()
    choice = ""
    print("Building the network map, please wait...")
    scan(hostList, credentials)
    print("Ready!")
    while choice != "exit":
        choice = str(input("> "))
        if choice == "uplist":
            print("List of reachable machines")
            for host in hostList:
                if hostList[host]:
                    print(host + " is up")
        elif choice == "help" or choice == "h":
            print("uplist : list all server up\nhelp : open this help\nexit : close pyUlbTools")
