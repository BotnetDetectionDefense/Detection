import pymysql


#### Connection to MySQL Database #####
myConnection = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
cur = myConnection.cursor()

class database_operation:

    def insert_data(self,Time, Protocol, Service, SourceIP, EthSource, SourcePort, DestinationIP, EthDestination, DestinationPort, Flags, ToS, Bytes):
        
        query = "INSERT INTO LiveTraffic (captime, protocol, service, sourceip, sourcemac, sourceport, destinationip, destinationmac, destinationport, flags, tos, bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        args = (Time, Protocol, Service, SourceIP, EthSource, SourcePort, DestinationIP, EthDestination, DestinationPort, Flags, ToS, Bytes)
        cur.execute(query, args)
        myConnection.commit()
    def disconnect_connection(self):
        myConnection.close()