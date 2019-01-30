#!/usr/bin/env python
#########################################################################
# Gregory Camp
# grcamp@cisco.com
# set_ucse_cimc_ip
#
# Testing Summary:
#   Not tested
#
# Usage:
#   ./reboot_cimc.py cimcs.txt -u username -p password
#
# Input File Format:
# CIMC IP Address
#
# Global Variables:
#   logger = Used for Debug output and script info
#   WORKER_COUNT = Maximum number of simultaneous threads
#   deviceCount = Used for tracking total device threads
##########################################################################

import os
import logging
import time
import argparse
import paramiko
import sys
import socket
import getpass
from multiprocessing.dummy import Pool as ThreadPool

# Declare global variables
logger = logging.getLogger(__name__)
WORKER_COUNT = 25
deviceCount = 0

def warning(msg):
    logger.warning(msg)


def error(msg):
    logger.error(msg)


def fatal(msg):
    logger.fatal(msg)
    exit(1)


#########################################################################
# Class CIMC
#
# Container for CIMC
#########################################################################
class CIMC:
    def __init__(self):
        self.ipAddress = ""
        self.username = ""
        self.password = ""
        self.interfaces = []
        self.deviceNumber = 0

    # Method configure_router
    #
    # Input: None
    # Output: None
    # Parameters: None
    #
    # Return Value: -1 on error, 0 for successful discovery
    #####################################################################
    def reboot_cimc(self):
        # Declare variables
        returnVal = 0

        # Open Log File
        myLogFile = open(self.ipAddress + "_log.txt", 'a')

        # Attempt to login to devices via SSH
        try:
            # Attempt Login
            remote_conn_pre = paramiko.SSHClient()
            # Bypass SSH Key accept policy
            remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Attempt to connection
            remote_conn_pre.connect(self.ipAddress, username=self.username, password=self.password, look_for_keys=False,
                                    allow_agent=False)
            # Log into WAE
            remote_conn = remote_conn_pre.invoke_shell()
            time.sleep(15)
            myOutput = remote_conn.recv(65535)
            myLogFile.write(myOutput)
            myLogFile.flush()

            # Check if user prompt appears
            if "#" not in myOutput:
                # if not exit method
                myLogFile.close()
                remote_conn.close()
                return -2

            # Login successful
            logger.info("Logged into {} - {} of {}".format(self.ipAddress, str(self.deviceNumber), str(deviceCount)))

            # Enter cimc scope
            remote_conn.send("scope cimc")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)

            # Reboot CIMC
            remote_conn.send("reboot")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile, prompt='?[y|N]')

            # Confirm
            remote_conn.send("y")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile, prompt='?[y|N]')
            # Confirm
            remote_conn.send("y")
            remote_conn.send("\n")

            time.sleep(1)
            myOutput = remote_conn.recv(65535)
            myLogFile.write(myOutput)

            # Close connection
            remote_conn.close()
            myLogFile.close()
        # Print exception and return -1
        except IOError as error:
            print("Invalid Hostname")
            myLogFile.close()
            return -1
        except paramiko.PasswordRequiredException as error:
            print("Invalid Username or password")
            myLogFile.close()
            return -2
        except paramiko.AuthenticationException as error:
            print("Invalid Username or password")
            myLogFile.close()
            return -2
        except socket.timeout as error:
            print("Connection timeout")
            myLogFile.close()
            return -1
        except Exception, e:
            print(str(e))
            myLogFile.close()
            return -1

        # Return success
        return returnVal

    # Method _wait_for_prompt
    #
    # Input: None
    # Output: None
    # Parameters: None
    #
    # Return Value: -1 on error, 0 for successful discovery
    #####################################################################
    def _wait_for_prompt(self, remote_conn, myLogFile, prompt="#", timeout=10):
        # Declare variables
        allOutput = ""
        i = 0

        # Change blocking mode to non-blocking
        remote_conn.setblocking(0)

        # Wait timeout seconds total
        while i < timeout:
            time.sleep(1)

            try:
                myOutput = remote_conn.recv(65535)
            except:
                myOutput = ""

            allOutput = allOutput + myOutput

            myLogFile.write(myOutput)
            myLogFile.flush()

            if prompt in myOutput:
                i = timeout

            i = i + 1

        # Change blocking mode to blocking
        remote_conn.setblocking(1)

        # Return None
        return allOutput

# Function build_cimc_list
#
# Input: None
# Output: None
# Parameters: None
#
# Return Value: None
#####################################################################
def build_cimc_list(cimcs, username, password):
    # Declare variables
    returnList = []
    i = 1
    
    logger.info("Building Router List")

    # Get configuration for each flex-connect group
    for line in cimcs:
        myCIMC = CIMC()
        myCIMC.ipAddress = line.strip()
        myCIMC.username = username
        myCIMC.password = password
        myCIMC.deviceNumber = i
        returnList.append(myCIMC)
        i += 1

    # Return None
    return returnList

# Function reboot_cimc_worker
#
# Input: None
# Output: None
# Parameters: string the_list, string subString
#
# Return Value: -1 of error, index of first occurrence if found
#####################################################################
def reboot_cimc_worker(device):
    # Declare variables
    global deviceCount

    if device.deviceNumber < 100:
        # Start thread at time of device number value
        time.sleep(device.deviceNumber)

    logger.info("Starting worker for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    i = device.configure_router()

    # If discovered, parse data
    if i == 0:
        logger.info("CIMC Reboot Complete for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
        return None
    # Else print error
    elif i == -2:
        logger.info("Bad username or password for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    elif i == -3:
        logger.info("CIMC Reboot Failed for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    else:
        logger.info("CIMC Reboot Failed for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))

    return None


# Function main
#
# Input: None
# Output: None
# Parameters: None
#
# Return Value: None
#####################################################################
def main(**kwargs):
    # Declare variables
    myRouters = []
    global deviceCount

    # Set logging
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s [%(levelname)8s]:  %(message)s")

    if kwargs:
        args = kwargs
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('input', help='Input File')
        parser.add_argument('-u', '--username', help='Username')
        parser.add_argument('-p', '--password', help='Password')

        args = parser.parse_args()

    # Check for username input
    if args.username == None:
        args.username = raw_input("Username: ")
    # Check for password input
    if args.password == None:
        args.password = getpass.getpass()

    # Open file
    myFile = open(args.input, 'r')
    # Read file into a list
    cimcList = [i for i in myFile]
    # Close file
    myFile.close()

    # Log info
    logger.info("Input File Imported")
    
    # Build router List
    cimcs = build_cimc_list(cimcList, args.username, args.password)
    
    # Set Device count
    deviceCount = len(myRouters)
    
    # Build Thread Pool
    pool = ThreadPool(WORKER_COUNT)
    # Launch worker
    results = pool.map(reboot_cimc_worker, cimcs)

    # Wait for all threads to complete
    pool.close()
    pool.join()


    # Return None
    return None


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        print str(e)
        os._exit(1)
