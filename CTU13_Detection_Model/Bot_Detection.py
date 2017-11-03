import numpy as np
import pandas as pd
#import mysql.connector

#conn = mysql.connector.connect(user='root', password = '1590', database='bot_detect_data')
import pymysql

conn = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
#cur = myConnection.cursor()


# Importing training data set\

X_train = pd.read_sql('SELECT duration, protocol, sourceport, destinationport, tos, packets, bytes, flows FROM CTUTrainData', con=conn)
Y_train = pd.read_sql('SELECT lables FROM CTUTrainData', con=conn)



# Importing test dataset

X_test=pd.read_sql('SELECT duration, protocol, sourceport, destinationport, tos, packets, bytes, flows FROM LiveTraffic', con=conn)
Souce_IP_Port = pd.read_sql('SELECT sourceip,sourcemac FROM LiveTraffic', con=conn)
X_result = pd.DataFrame()
X_result = X_test.copy(deep=True)
#remove trailing spaces in column names
X_test.rename(columns=lambda x: x.strip(),inplace=True)



# Label encoding the data

from sklearn.preprocessing import LabelEncoder
le=LabelEncoder()
column = ['protocol']
for col in column:
    if X_test[col].dtypes=='object':
        data=X_train[col].append(X_test[col])
        le.fit(data.values)
        X_train[col]=le.transform(X_train[col])
        X_test[col]=le.transform(X_test[col])


# One hot encoding of the label encoded data
        
from sklearn.preprocessing import OneHotEncoder
enc=OneHotEncoder(sparse=False)
columns=['protocol']
for col in columns:
   data=X_train[[col]].append(X_test[[col]])
   enc.fit(data)
   Proto = enc.transform(X_train[[col]])
   Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col]
        .value_counts().index])
   Proto=Proto.set_index(X_train.index.values)
   X_train = X_train.drop(col, axis = 1)
   X_train=pd.concat([X_train,Proto],axis=1)
   Proto = enc.transform(X_test[[col]])
   Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col]
        .value_counts().index])
   Proto=Proto.set_index(X_test.index.values)
   X_test = X_test.drop(col, axis = 1)
   X_test=pd.concat([X_test,Proto],axis=1)


Y_train = (np.ravel(Y_train))


# Implementing SVM model to train the model

from sklearn.svm import SVC
clf = SVC()
clf.fit(X_train, Y_train) 
SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0,
    decision_function_shape=None, degree=3, gamma='auto', kernel='rbf',
    max_iter=-1, probability=False, random_state=None, shrinking=True,
    tol=0.001, verbose=False)
predict_out = clf.predict(X_test)


# Converting prediction data to a data frame

predict_out = pd.DataFrame(data=predict_out)
#print(predict_out)


# Trackig the bot IPs

Prediction = Souce_IP_Port.join(predict_out)
Prediction = Prediction.join(X_result)
Bots = pd.DataFrame()
Bots = Prediction[Prediction[0] == 'Botnet\r']
#print(Prediction[0])
Bot_IP = Bots.drop_duplicates(subset=None, keep='first', inplace=False)
#print(Bot_IP['sourceip'])


for index, row in Bot_IP.iterrows():
    cur = conn.cursor()
    query = "INSERT INTO CTUTrainData (duration, protocol, sourceport, destinationport, tos, packets, bytes, flows, lables) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    args = (row['duration'], row['protocol'],row['sourceport'], row['destinationport'],row['tos'],row['packets'],row['bytes'],row['flows'],row[0])
    cur.execute(query, args)
    conn.commit()
    
writer = pd.ExcelWriter('output.xlsx')
Bot_IP.to_excel(writer,'Sheet1')
writer.save()