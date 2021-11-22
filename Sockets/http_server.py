# Author: Corey McFarland
# Date: 10/17/2021
# Desc: Project 1 - Simple Server

# Used code from K&R Chapter 2.7 as a starting point
from socket import *

# Connect to host via HTTP port 80
serverName = 'localhost'
serverPort = 4462
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind((serverName, serverPort))
serverSocket.listen(1)
print('Server is active on port ', serverPort)

data = "HTTP/1.1 200 OK\r\n"\
    "Content-Type: text/html; charset=UTF-8\r\n\r\n"\
    "<html>Congratulations! You've downloaded the first Wireshark lab file!</html>\r\n"

while(True):
    connectionSocket, addr = serverSocket.accept()
    serverReceive = connectionSocket.recv(1024).decode()
    receiveSize = len(serverReceive)
    if (receiveSize > 0):
        print('Connected by ', connectionSocket.getsockname())
        print('Received: ', serverReceive)
        print('======Sending======')
        print(data)
        print('===================')
        connectionSocket.send(data.encode())
        connectionSocket.close()
        break
    
    connectionSocket.close()