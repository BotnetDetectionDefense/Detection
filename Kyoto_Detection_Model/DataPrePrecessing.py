import pymysql

myConnection = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
cur = myConnection.cursor()
query = "Select count from LiveTraffic t1,LiveTraffic t2 WHERE duration between duration and %s and t1.destinationip = t2.destinationip and ti.sourceip=t2.sourceip and t1.id<>t2.id"
    #print(query)
args = (d)
cur.execute(query, args)
myConnection.commit()

myConnection.close()