import pyshark
import pymysql

myConnection = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
cur = myConnection.cursor()

cap = pyshark.FileCapture('example.pcap')
i = 1
j = 1
scale = 16
num_of_bits = 8
for packet in cap:
    #print("----------- ", i, " -----------")
    try:
        ServiceList = []
        ServiceList = list(packet.layers)
        #print("Service List: ", ServiceList[3].layer_name)
        #print(ServiceList)
        if ((len(ServiceList)>3) and ServiceList[3].layer_name != "http"):
            Service = packet.highest_layer
        else:
            Service =ServiceList[3].layer_name
    except:
        Service = "Other"
        #print(Service)
    print(Service)
    try:
        EthSource = str(packet.eth.src_resolved)
        #print("Eth Source: ", EthSource)
        EthDestination = str(packet.eth.dst_resolved)
        #print("Eth Destination", EthDestination)
        Duration = str(packet.frame_info.time_delta)
        #print("Duration: ", Duration)
        Flows = "1"
        #print("Flows: ", Flows)
        IPType = packet.eth.type
        #print(IPType)
        # IP version 4
        if(IPType == "0x00000800"):
            #print("IPv4")
            proto = packet.ip.proto
            #print(proto)
            if (proto == "6"):
                Protocol = "TCP"
                #print(Protocol)
            elif(proto == "17"):
                Protocol = "UDP"
            elif(proto == "1"):
                Protocol = "ICMP"
                #print(Protocol)
            else:
                Protocol = None
                #print(Protocol)
            #print("Protocol: ", Protocol)
            SourceIP = str(packet.ip.src)
            #print("Source IP: ", SourceIP)
            DestinationIP = str(packet.ip.dst)
            #print("Destination IP: ", DestinationIP)
            ToS = str(bin(int(packet.ip.dsfield, scale))[2:].zfill(num_of_bits))
            #print("ToS: ", ToS)
            TotalLength = int(packet.ip.len)
            HeaderLength = int(packet.ip.hdr_len)
            #print("H Len: ", HeaderLength)
            NoOfBytes = TotalLength - HeaderLength
            Bytes = str(NoOfBytes)
            #print("Bytes: ", Bytes)
            Length = str(packet.length)
            #print("Length: ", Length)
        # IP version 6
        elif(IPType == "0x000086dd"):
            #print("IPv6")
            proto = packet.ipv6.nxt
            #print(proto)
            if (proto == "6"):
                Protocol = "TCP"
                #print(Protocol)
            elif(proto == "17"):
                Protocol = "UDP"
                #print(Protocol)
            elif(proto == "58"):
                Protocol = "ICMPv6"
                #print(Protocol)
            else:
                Protocol = None
            #print("Protocol: ", Protocol)
            SourceIP = str(packet.ipv6.src)
            #print("Source IP: ", SourceIP)
            DestinationIP = str(packet.ipv6.dst)
            #print("Destination IP: ", DestinationIP)
            ToS = str(bin(int(packet.ipv6.tclass, scale))[2:].zfill(num_of_bits))
            #print("ToS: ", ToS)
            Bytes = str(packet.ipv6.plen)
            #print("Bytes: ", Bytes)
            Length = str(packet.captured_length)
            #print("Length: ", Length)

        if(proto == "6"):
            SourcePort = str(packet.tcp.srcport)
            #print("Source Port: ", SourcePort)
            DestinationPort = str(packet.tcp.dstport)
            #print("Destination Port: ", DestinationPort)
            Flags = str(bin(int(packet.tcp.flags, scale))[2:].zfill(num_of_bits))
            #print("Falgs: ", Flags)
        elif(proto == "17"):
            SourcePort = str(packet.udp.srcport)
            #print("Source Port: ", SourcePort)
            DestinationPort = str(packet.udp.dstport)
            #print("Destination Port: ", DestinationPort)
            Flags = "00000000"
            #print("Falgs: ", Flags)
        else:
            SourcePort = "7"
            #print("Source Port: ", SourcePort)
            DestinationPort = "7"
            #print("Destination Port: ", DestinationPort)
            Flags = "00000000"
            #print("Falgs: ", Flags)
        i = i+1
        query = "INSERT INTO LiveTraffic (duration, protocol, service, sourceip, sourcemac, sourceport, destinationip, destinationmac, destinationport, flags, tos, packets, bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        #print(query)
        args = (Duration, Protocol, Service, SourceIP, EthSource, SourcePort, DestinationIP, EthDestination, DestinationPort, Flags, ToS, Length, Bytes)
        cur.execute(query, args)
        myConnection.commit()
        j = j+1
    except:
        #print("Broadcast Packet")
        i = i+1
        pass
myConnection.close()
print(i)
print(j)