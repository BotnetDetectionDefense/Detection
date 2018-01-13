import pyshark
import Database

DB = Database.database_operation()
i = 0
cap = pyshark.FileCapture('capture.pcap')
scale = 16
num_of_bits = 8
for packet in cap:
    ##### Service #####
    try:
        ServiceList = []
        ServiceList = list(packet.layers)
        if ((len(ServiceList)>3) and ServiceList[3].layer_name != "http"):
            Service = packet.highest_layer
        else:
            Service =ServiceList[3].layer_name
    except:
        Service = "Other"

    print(Service)
    try:
        ##### Source and Destination MAC Address #####
        try:
            EthDestination = str(packet.eth.dst_resolved)
            EthSource = str(packet.eth.src_resolved)
        except:
            EthSource = str(packet.sll.src_eth)
            EthDestination = "00:00:00:00:00:00"

        ##### Start Time of a Packet #####
        Time = packet.frame_info.time_relative
        #print(Time)

        ##### IP Version #####
        IPType = packet.sll.etype

        ##### 0x00000800 = IPv4 #####
        if(IPType == "0x00000800"):
            
            ##### Transport Layer Protocol #####
            proto = packet.ip.proto
            if (proto == "6"):
                Protocol = "TCP"
            elif(proto == "17"):
                Protocol = "UDP"
            elif(proto == "1"):
                Protocol = "ICMP"
            else:
                Protocol = None


            ##### Source and Destination IP #####
            SourceIP = str(packet.ip.src)
            DestinationIP = str(packet.ip.dst)

            ##### Type of Service #####
            ToS = str(bin(int(packet.ip.dsfield, scale))[2:].zfill(num_of_bits))

            ##### Payload Length #####
            TotalLength = int(packet.ip.len)
            HeaderLength = int(packet.ip.hdr_len)
            NoOfBytes = TotalLength - HeaderLength
            Bytes = int(NoOfBytes)

        ##### 0x000086dd = IPv6 #####
        elif(IPType == "0x000086dd"):
            
            ##### Transport Layer Protocol #####
            proto = packet.ipv6.nxt
            if (proto == "6"):
                Protocol = "TCP"
            elif(proto == "17"):
                Protocol = "UDP"
            elif(proto == "58"):
                Protocol = "ICMPv6"
            else:
                Protocol = None

            ##### Source and Destination IP #####
            SourceIP = str(packet.ipv6.src)
            DestinationIP = str(packet.ipv6.dst)

            ##### Type Of Service #####
            ToS = str(bin(int(packet.ipv6.tclass, scale))[2:].zfill(num_of_bits))

            ##### Payload Length #####
            Bytes = int(packet.ipv6.plen)

        ##### Flag, Source and Destination Protocol #####
        if(proto == "6"):
            SourcePort = str(packet.tcp.srcport)
            DestinationPort = str(packet.tcp.dstport)
            Flags = str(bin(int(packet.tcp.flags, scale))[2:].zfill(num_of_bits))
        elif(proto == "17"):
            SourcePort = str(packet.udp.srcport)
            DestinationPort = str(packet.udp.dstport)
            Flags = "00000000"
        else:
            SourcePort = "7"
            DestinationPort = "7"
            Flags = "00000000"

        ##### Insert the captured data to the LiveTraffic Table #####
        DB.insert_data(Time, Protocol, Service, SourceIP, EthSource, SourcePort, DestinationIP, EthDestination, DestinationPort, Flags, ToS, Bytes)
        i = i +1
    
    except:
        pass
        
