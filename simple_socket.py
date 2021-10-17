# Author: Corey McFarland
# Date: 10/17/2021
# Desc: Project 1 - Socket GET Requests

# Used code from K&R Chapter 2.7 as a starting point
from socket import *

def partOne(projectSocket):
    # Function to send a GET request for a small file
    projectRequest = 'GET /wireshark-labs/INTRO-wireshark-file1.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n'
    projectSocket.send(projectRequest.encode())
    projectRecieve = projectSocket.recv(1024)
    print('[RECV] - length: ', len(projectRecieve))
    print(projectRecieve.decode())
    return

def partTwo(projectSocket):
    # Function to send a GET request for a large file
    projectRequest = 'GET /wireshark-labs/HTTP-wireshark-file3.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n'
    projectSocket.send(projectRequest.encode())
    
    # Read until projectRecieve has no content.
    while(True):
        projectRecieve = projectSocket.recv(1024)
        receiveSize = len(projectRecieve)
        if(receiveSize <= 0):
            break
        print('[RECV] - length: ', receiveSize)
        print(projectRecieve.decode())
    return

if __name__ == "__main__":
    # Connect to host via HTTP port 80
    serverName = 'gaia.cs.umass.edu'
    serverPort = 80
    projectSocket = socket(AF_INET, SOCK_STREAM)
    projectSocket.connect((serverName, serverPort))


    print("Part One:")
    partOne(projectSocket)
    print("Part Two:")
    partTwo(projectSocket)

    projectSocket.close()