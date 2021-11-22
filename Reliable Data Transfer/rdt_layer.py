from segment import Segment


# #################################################################################################################### #
# RDTLayer                                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable         #
# channel.                                                                                                             #
#                                                                                                                      #
#                                                                                                                      #
# Notes:                                                                                                               #
# This file is meant to be changed.                                                                                    #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class RDTLayer(object):
    # ################################################################################################################ #
    # Class Scope Variables                                                                                            #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    DATA_LENGTH = 4 # in characters                     # The length of the string data that will be sent per packet...
    FLOW_CONTROL_WIN_SIZE = 15 # in characters          # Receive window size for flow-control
    sendChannel = None
    receiveChannel = None
    dataToSend = ''
    currentIteration = 0                                # Use this for segment 'timeouts'
    countSegmentTimeouts = 0
    # Add items as needed

    # ################################################################################################################ #
    # __init__()                                                                                                       #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.dataReceived = {}
        self.seqReceived = []
        self.seqIndex = 0
        self.currentIteration = 0
        self.currentSeq = 0
        self.currentAck = 0
        self.resendCount = 0
        self.resendSeq = 0
        self.resendAck = 0
        self.segmentTime = 0
        self.countSegmentTimeouts = 0
        # Add items as needed

    # ################################################################################################################ #
    # setSendChannel()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable sending lower-layer channel                                                 #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setSendChannel(self, channel):
        self.sendChannel = channel

    # ################################################################################################################ #
    # setReceiveChannel()                                                                                              #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable receiving lower-layer channel                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # ################################################################################################################ #
    # setDataToSend()                                                                                                  #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the string data to send                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setDataToSend(self,data):
        self.dataToSend = data

    # ################################################################################################################ #
    # getDataReceived()                                                                                                #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to get the currently received and buffered string data, in order                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getDataReceived(self):
        # ############################################################################################################ #
        # Identify the data that has been received...
        tempStr = ''

        for seq in self.seqReceived:
            tempStr += self.dataReceived[str(seq)]

        # ############################################################################################################ #
        return tempStr

    # ################################################################################################################ #
    # processData()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # "timeslice". Called by main once per iteration                                                                   #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processData(self):
        self.currentIteration += 1
        self.processSend()
        self.processReceiveAndSendRespond()

    # ################################################################################################################ #
    # processSend()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment sending tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processSend(self):

        # ############################################################################################################ #

        # You should pipeline segments to fit the flow-control window
        # The flow-control window is the constant RDTLayer.FLOW_CONTROL_WIN_SIZE
        # The maximum data that you can send in a segment is RDTLayer.DATA_LENGTH
        # These constants are given in # characters

        totalsize = len(self.dataToSend)
        maxseg = self.FLOW_CONTROL_WIN_SIZE // self.DATA_LENGTH
        seqend = self.seqIndex + self.DATA_LENGTH

        # Somewhere in here you will be creating data segments to send.
        # The data is just part of the entire string that you are trying to send.
        # The seqnum is the sequence number for the segment (in character number, not bytes)

        while True:
            # Check for full window 
            if (len(self.sendChannel.sendQueue) >= maxseg - len(self.receiveChannel.receiveQueue)):
                break

            # Check for end of data
            if (self.seqIndex >= totalsize):
                break

            elif (seqend > totalsize):
                seqend = totalsize

            data = self.dataToSend[self.seqIndex:seqend]

            # ############################################################################################################ #
            # Display sending segment
            segmentSend = Segment()
            segmentSend.setData(str(self.currentSeq),data)
            print("Sending segment: ", segmentSend.to_string())

            # Use the unreliable sendChannel to send the segment
            self.sendChannel.send(segmentSend)

            # Update indices
            self.seqIndex = seqend
            self.currentSeq = self.seqIndex
            seqend = self.seqIndex + self.DATA_LENGTH
            

    # ################################################################################################################ #
    # processReceive()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment receive tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processReceiveAndSendRespond(self):
        # Segment acknowledging packet(s) received

        # This call returns a list of incoming segments (see Segment class)...
        tempRec = []
        listIncomingSegments = self.receiveChannel.receive()

        # ############################################################################################################ #
        # What segments have been received?
        # How will you get them back in order?
        # This is where a majority of your logic will be implemented

        # ############################################################################################################ #
        # How do you respond to what you have received?
        # How can you tell data segments apart from ack segemnts?

        # Somewhere in here you will be setting the contents of the ack segments to send.
        # The goal is to employ cumulative ack, just like TCP does...

        if (len(listIncomingSegments) == 0):
            print('Nothing recevied.')
            if (len(self.dataToSend) - self.currentAck > 0 and self.segmentTime == 0):
                self.segmentTime = 1

        # Order segments received
        for seg in listIncomingSegments:
            # Add to empty list
            if (len(tempRec) == 0):
                tempRec.append(seg)
                continue
            i = 0

            # Check if sent by client
            if (int(seg.acknum) < 0):

                # Insert in ascending order
                for tseg in tempRec:
                    if (int(seg.acknum) < int(tseg.acknum)):
                        tempRec.insert(i, seg)
                        break
                    i += 1
                
                if (i == len(tempRec)):
                    tempRec.append(seg)

            # Otherwise sent by server
            else:
                # Insert in ascending order
                for tseg in tempRec:
                    if (int(seg.seqnum) < int(tseg.seqnum)):
                        tempRec.insert(i, seg)
                        break
                    i += 1

                if (i == len(tempRec)):
                    tempRec.append(seg)

        # Check status of segements
        for seg in tempRec:
            # Check if ACK is in order for client
            if (int(seg.acknum) >= self.currentAck + min(self.DATA_LENGTH, len(self.dataToSend) - self.currentAck)):
                self.currentAck = int(seg.acknum)
                self.segmentTime = 0
                print("Client - In-order ACK received: " + str(self.currentAck))

            # Otherwise prepare to resend missing SEQ
            elif (int(seg.seqnum) < 0):
                print("Client - Out of order ACK received: " + str(seg.acknum) + ", Expected: " +
                      str(self.currentAck + min(self.DATA_LENGTH, len(self.dataToSend) - self.currentAck)))

                self.segmentTimeout = 1

                # Continue until ACK repeated three times
                if (self.resendAck == int(seg.acknum)):
                    self.resendCount += 1
                    print("Recieved (" + str(self.resendCount) + ") Copy of ACK: " + str(self.resendAck))

                    # Check to resend segment after three or more repeated ACKs
                    if (self.resendCount >= 3):
                        data = self.dataToSend[int(seg.acknum):int(seg.acknum) + self.DATA_LENGTH]

                        # Display sending segment
                        segmentSend = Segment()
                        segmentSend.setData(int(seg.acknum), data)
                        print("Resending segment: ", segmentSend.to_string())

                        # Use the unreliable sendChannel to send the segment
                        self.sendChannel.send(segmentSend)

                else:
                    self.resendAck = int(seg.acknum)
                    self.resendCount = 1

            # Check if SEQ is in order for server
            if (int(seg.seqnum) <= self.currentSeq and int(seg.seqnum) >= 0):
                # Verify ACK
                if not (seg.checkChecksum()):
                    print("Invalid Checksum")
                    self.currentSeq = int(seg.seqnum)

                    # Display response segment
                    acknum = self.currentSeq
                    segmentAck = Segment()
                    segmentAck.setAck(str(acknum))
                    print("Sending ack: ", segmentAck.to_string())

                    # Use the unreliable sendChannel to send the ACK packet
                    self.sendChannel.send(segmentAck)
                    continue

                # Add data
                self.dataReceived[str(seg.seqnum)] = seg.payload

                if int(seg.seqnum) not in self.seqReceived:
                    self.seqReceived.append(int(seg.seqnum))
                    self.seqReceived.sort()

                # Check if SEQ was missing from data
                for i, seq in enumerate(self.seqReceived):
                    if (i + 1 >= len(self.seqReceived)):
                        self.currentSeq = self.seqReceived[-1] + self.DATA_LENGTH
                        
                    elif (self.seqReceived[i + 1] - seq > self.DATA_LENGTH):
                        self.currentSeq = seq + self.DATA_LENGTH
                        break

                print("Sever - In-order SEQ received: " + str(self.currentSeq))

                # Display response segment
                acknum = self.currentSeq
                segmentAck = Segment()
                segmentAck.setAck(str(acknum))
                print("Sending ack: ", segmentAck.to_string())

                # Use the unreliable sendChannel to send the ACK packet
                self.sendChannel.send(segmentAck)
            
            # Otherwise resend missing ACK
            elif (int(seg.acknum) < 0):
                print("Server - Out of order Seq recevied: " + str(seg.seqnum) + ", Expected: " + str(self.currentSeq))

                # Verify ACK
                if not (seg.checkChecksum()):
                    print("Invalid Checksum")
                    self.currentSeq = int(seg.seqnum)

                    # Display response segment
                    acknum = self.currentSeq
                    segmentAck = Segment()
                    segmentAck.setAck(str(acknum))
                    print("Sending ack: ", segmentAck.to_string())

                    # Use the unreliable sendChannel to send the ACK packet
                    self.sendChannel.send(segmentAck)
                    continue

                if str(seg.seqnum) not in self.dataReceived:
                    self.dataReceived[str(seg.seqnum)] = seg.payload
                
                if int(seg.seqnum) not in self.seqReceived:
                    self.seqReceived.append(int(seg.seqnum))
                    self.seqReceived.sort()

                # Display response segment
                acknum = self.currentSeq
                segmentAck = Segment()
                segmentAck.setAck(str(acknum))
                print("Sending ack: ", segmentAck.to_string())

                # Use the unreliable sendChannel to send the ack packet
                self.sendChannel.send(segmentAck)

            
        # Check for segments waiting

        if (self.segmentTime > 0):
                self.segmentTime += 1

                # Timeout a segment
                if (self.segmentTime >= 5):
                    print("Segemnt Timeout")
                    self.countSegmentTimeouts += 1

                    # Reset timer
                    self.segmentTime = 0

                    # Check data length
                    seqend = self.currentAck + self.DATA_LENGTH
                    if (seqend >= len(self.dataToSend)):
                        seqend = len(self.dataToSend)

                    # Resend segement
                    data = self.dataToSend[self.currentAck:seqend]

                    # Display sending segment
                    segmentSend = Segment()
                    segmentSend.setData(self.currentAck, data)
                    print("Resending segment: ", segmentSend.to_string())

                    # Use the unreliable sendChannel to send the segment
                    self.sendChannel.send(segmentSend)
