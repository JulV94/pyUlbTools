#!/usr/bin/python3

from pexpect import pxssh
from threading import Thread
import getpass, json, queue

class ScanThread(Thread):

    def __init__(self, hostname, credentials, queue):
        Thread.__init__(self)
        self.hostname = hostname
        self.credentials = credentials
        self.queue = queue

    def run(self):
        s = pxssh.pxssh()
        try:
            s.login(self.hostname, self.credentials[0], self.credentials[1], login_timeout=5)
            s.logout()
            self.queue.put((self.hostname, True))
        except pxssh.ExceptionPxssh:
            self.queue.put((self.hostname, False))


def init():
    print("Welcome to pyUlbTools")
    username = str(input("Username : "))
    password = getpass.getpass("Password : ")
    return username, password

def scan(host_list, credentials):
    thread_pool = []
    q = queue.Queue()
    results = []
    for hostname in host_list:
        thread = ScanThread(hostname,credentials, q)
        thread_pool.append(thread)
        thread.start()
    for thread in thread_pool:
        results.append(q.get())
        thread.join()
    return results

if __name__ == '__main__':
    credentials = init()
    with open('hosts.json') as hosts_f:
        hostList = json.load(hosts_f)
    print("Scanning...")
    results = scan(hostList["sca"], credentials)
    for res in results:
        print(res[0] + " up : " + str(res[1]))
