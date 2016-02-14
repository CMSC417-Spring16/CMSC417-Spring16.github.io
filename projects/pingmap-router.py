#!/usr/bin/python

import socket
import sys
import getopt
import random
import time
import os
import struct
import pprint

def handle(myID, sock, payload, nodes, links, forward, rand):
    # split payload into header and actual payload
    header = payload[:6]
    payload = payload[6:]

    # parse header
    (typ, version, TTL, hdrLenPlusFlags, source, dest) = struct.unpack( "BBBBBB", header )
    hdr_len = (hdrLenPlusFlags & 0xF0) >> 4
    flags = (hdrLenPlusFlags & 0x0F)
    # print "Received packet:\n  type: %hu\n  version: %hu\n  TTL: %hu\n  hdr_len: %hu\n  flags: %hu\n  source: %hu\n  dest: %hu\n" % (typ, version, TTL, hdr_len, flags, source, dest)

    if (flags > 1):
        # don't respond to messages with flags
        print "Dropping packet with flags set to %#x" % flags
        sys.exit()

    elif (dest == myID):
        # it's for me, respond
        TTL = 255
        dest = source
        source = myID
        flags = 0x0
        print "Responding to packet for me"

    elif (TTL <= 1):
        # it's not for me, and the TTL expired, send error
        TTL = 255
        dest = source
        source = myID
        flags = 0x1 #set TTL expired flag
        print "Sending TTL expired error message"

    else:
        # it's not for me, decrement TTL and forward
        TTL = TTL-1
        print "Forwarding message"

    # build response/forward header
    #                                                       hdr_length
    resp_header = struct.pack( "BBBBBB", typ, version, TTL, (0x3 << 4) | flags,
                                         source, dest )

    nextHop = -1
    if(dest in forward):
        nextHop = int(forward[dest])
    else:
        print "No forwarding entry to get to %d from %d" % (dest, myID)
        sys.exit()
    if (myID,nextHop) not in links:
        print "Next hop is %d, but there is no link from %d to %d" % (nextHop, myID, nextHop)
        sys.exit()

    (latency, loss) = links[(myID,nextHop)]
    if rand < loss:
        print "Dropping message"
        sys.exit()

    time.sleep(latency/1000.0)
    sock.sendto(resp_header + payload, ("127.0.0.1",nodes[nextHop]))

    sys.exit()

def checkPort(port):
    if port<=1023 or port>65535:
        assert False, "Invalid port "+port+": ports must be in the range 1024-65535"
    return port

def checkNodeID(nodeID):
    if nodeID<=0 or nodeID>255:
        assert False, "Invalid node ID "+nodeID+": node IDs must be in the range 1-255"
    return nodeID

def checkLoss(loss):
    if loss<0.0 or loss>1.0:
        assert False, "Invalid loss rate "+loss+": loss rates must be in the range 0.0-1.0"
    return loss

def checkLatency(latency):
    if latency<0:
        assert False, "Invalid latency "+latency+": latencies must be positive"
    return latency

def usage(args):
    sys.stderr.write("usage: python {0} -l -r -n\n".format(args[0]))

if __name__ == "__main__":
    configFile = "config"
    myID = 2
    clientID = 1
    myPort = -1
    links = dict()
    nodes = dict()
    forward = dict()
    nodePorts = dict()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:d:", ["config-file=", "id="])

    except getopt.GetoptError as err:
        print str(err)
        usage(sys.argv)
        sys.exit(1)

    for o, a in opts:
        if o in ("-f", "--config-file"):
            configFile = a
        elif o in ("-d", "--id"):
            myID = checkNodeID(int(a))
        else:
            assert False, "unhandled option"

    checkNodeID(myID)

    # parse the config file
    lines = list(open(configFile))
    for line in lines:
        words = line.split()
        if ( len(words) < 1 or (words[0] == "link" and len(words) != 5) or (words[0] == "node" and len(words) != 3) or (words [0] == "forward" and len(words) !=4) ):
            assert False, "invalid line %s" % line

        elif ( words[0] == "node" ):
            node = checkNodeID(int(words[1]))
            if ( words[2] == "client" ):
                clientID = node
            else:
                port = checkPort(int(words[2]))
                nodes[node] = port
                nodePorts[port] = 0 #to track the ports for nodes
                if node == myID:
                    myPort = port

        elif (words[0] == "link" ):
            node1 = checkNodeID(int(words[1]))
            node2 = checkNodeID(int(words[2]))
            latency, loss = checkLatency(int(words[3])), checkLoss(float(words[4]))

            #put the link in both ways just to be sure
            links[(node1,node2)] = (latency, loss)
            links[(node2,node1)] = (latency, loss)

        elif (words[0] == "forward" ):
            currNode = checkNodeID(int(words[1]))
            destNode = checkNodeID(int(words[2]))
            nextNode = checkNodeID(int(words[3]))

            #only store this node's forwarding entries
            if currNode == myID:
                forward[destNode] = nextNode

    print "Nodes: "+pprint.pformat(nodes)
    print "Links: "+pprint.pformat(links)
    print "NodeID: %d" % myID
    print "Forwarding table: "+pprint.pformat(forward)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', myPort))
    while 1:
        payload, client = sock.recvfrom(256)

        # hack that assumes somebody talking to us from a port other than a pingmap-router port is the client node
        # this means we can only handle one client at a time
        clientIP, clientPort = client
        if clientPort not in nodePorts:
            # populate the port of the clien in the nodes table
            nodes[clientID] = clientPort
            # sleep the appropriate time for the client link to this node
            latency, loss = links[(clientID,myID)]
            time.sleep(latency/1000.0)

        #this needs to be done in the parent process to avoid generating the same number every time
        rand = random.random()

        if (os.fork() == 0):
            handle(myID, sock, payload, nodes, links, forward, rand)
