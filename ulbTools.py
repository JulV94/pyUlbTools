#!/usr/bin/python3

from pexpect import pxssh
import getpass


def init():
    print("Welcome to pyUlbTools")
    username = str(input("Username : "))
    password = getpass.getpass("Password : ")
    return username, password


def scan(host_list, credentials):
    for machine in host_list:
        print(machine+" up : "+str(is_up(machine, credentials)))


def is_up(hostname, credentials):
    s = pxssh.pxssh()
    try:
        s.login(hostname, credentials[0], credentials[1], login_timeout=5)
        s.logout()
        return True
    except pxssh.ExceptionPxssh:
        return False


if __name__ == '__main__':
    credentials = init()
    hostList = ["sca-xt01.ulb.ac.be", "sca-xt02.ulb.ac.be", "sca-xt03.ulb.ac.be", "sca-xt04.ulb.ac.be"]
    scan(hostList, credentials)
