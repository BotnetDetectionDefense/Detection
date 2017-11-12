import numpy as np
import pandas as pd
import pymysql

conn = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
#cur = myConnection.cursor()


# Importing traning dataset

Train_Data=pd.read_sql('SELECT * FROM CTUTrainData', con=conn)
X_train = Train_Data[['duration', 'protocol', 'sourceport', 'destinationport', 'packets', 'bytes']]
Y_train = Train_Data[['lables']]


# Data pre-processing of the test data

#Importing the live traffic data
Test_Data = pd.read_sql('SELECT * FROM LiveTraffic', con=conn)
i=0
data = pd.DataFrame(columns=["protocol", "sourceip",'destinationip','sourceport','destinationport','count'])
#final = pd.DataFrame(columns=["protocol", "sourceip",'destinationip','sourceport','destinationport'], data=[[5,np.nan]])
x = Test_Data[['protocol','sourceip','destinationip','sourceport','destinationport']]
for index, row in x.iterrows():
    count = 0
    a = row['protocol'], row['sourceip'], row['destinationip'], row['sourceport'], row['destinationport']
    for index, row in x.iterrows():
        b = row['protocol'], row['sourceip'], row['destinationip'], row['sourceport'], row['destinationport']
        if(a==b):
            count = count + 1
    data['protocol'].append(row['protocol'])
    data['sourceip'].append(row['sourceip'])
    data['destinationip'].append(row['destinationip'])
    data['sourceport'].append(row['sourceport'])
    data['destinationport'].append(row['destinationport'])
    data['count'].append(count)
    print(a)
    print("row number: ", i, ", ", " Count: ",  count)
    i=i+1

X_test = 
X_result = pd.DataFrame()
X_result = X_test.copy(deep=True)
X_test.rename(columns=lambda x: x.strip(),inplace=True)

# Label encoding the data
from sklearn.preprocessing import LabelEncoder
le=LabelEncoder()
column = ['protocol','service']
for col in column:
    if X_test[col].dtypes=='object':
        data=X_train[col].append(X_test[col])
        le.fit(data.values)
        X_train[col]=le.transform(X_train[col])
        X_test[col]=le.transform(X_test[col])


# One hot encoding of the label encoded data
from sklearn.preprocessing import OneHotEncoder
enc=OneHotEncoder(sparse=False)
columns=['protocol', 'service']
for col in columns:
    data=X_train[[col]].append(X_test[[col]])
    enc.fit(data)
    Proto = enc.transform(X_train[[col]])
    Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col].value_counts().index])
    Proto=Proto.set_index(X_train.index.values)
    X_train = X_train.drop(col, axis = 1)
    X_train=pd.concat([X_train,Proto],axis=1)
    Proto = enc.transform(X_test[[col]])
    Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col].value_counts().index])
    Proto=Proto.set_index(X_test.index.values)
    X_test = X_test.drop(col, axis = 1)
    X_test=pd.concat([X_test,Proto],axis=1)




# Implementing SVM model to train the model

from sklearn.svm import SVC
#from sklearn.metrics import accuracy_score
clf = SVC()
clf.fit(X_train, Y_train)
SVC(C=10000.0, cache_size=100000, class_weight=None, coef0=100.0,
    decision_function_shape='ovr', degree=3, gamma=1000, kernel='poly',
    max_iter=-1, probability=True, random_state=1000, shrinking=False,
    tol=0.001, verbose=False)
predict_out = clf.predict(X_test)
predict_out = pd.DataFrame(data=predict_out)


# Trackig the bot IPs

Prediction = Souce_IP_Port.join(predict_out)
Prediction = Prediction.join(X_result)
Bots = pd.DataFrame()
Background = pd.DataFrame()
Legitimate = pd.DataFrame()
Bots = Prediction[Prediction[0] == 'Botnet\r']
Background = predict_out[predict_out[0] == 'Background\r']
Legitimate = predict_out[predict_out[0] == 'LEGITIMATE\r']
#print (accuracy_score(Y_test, predict_out))


#Insert the the bot data into traning table

for index, row in Bots.iterrows():
    cur = conn.cursor()
    query = "INSERT INTO CTUTrainData (duration, protocol, sourceport, destinationport, tos, packets, bytes, flows, lables) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    args = (row['duration'], row['protocol'],row['sourceport'], row['destinationport'],row['tos'],row['packets'],row['bytes'],row['flows'],row[0])
    cur.execute(query, args)
    conn.commit()

