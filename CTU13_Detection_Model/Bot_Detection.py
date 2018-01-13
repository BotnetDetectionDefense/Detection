import numpy as np
import pandas as pd
import pymysql
def database():
        conn = pymysql.connect(host ='localhost' ,user='root', password = 'root', database='bot_detect_data')
        # Importing traning dataset
        Train_Data=pd.read_sql('SELECT * FROM TrainingData', con=conn)
        X_train = Train_Data[['duration', 'protocol', 'sourceport', 'destinationport', 'packets', 'bytes']]
        Y_train = Train_Data[['label']]
        # Data pre-processing of the test data Importing the live traffic data
        Live_Data = pd.read_sql('SELECT * FROM LiveTraffic', con=conn)
        return(X_train, Y_train, Live_Data, conn)

def processing(Live_Data):
        Test_Data = Live_Data.drop_duplicates(subset=['protocol','sourceip','destinationip','sourceport','destinationport'], keep='first', inplace=False)
        del Test_Data['flags'] 
        del Test_Data['tos']
        del Test_Data['id']
        for index1, row1 in Test_Data.iterrows():
                count = 0
                destinationip03 = row1['destinationip']
                sourceip03 = row1['sourceip']
                sourceport03 = row1['sourceport']
                destinationport03 = row1['destinationport']
                protocol03 = row1['protocol']
                for index2, row2 in Test_Data.iterrows():
                        protocol04 = row2['protocol']
                        sourceport04 = row2['sourceport']
                        destinationport04 = row2['destinationport']
                        destinationip04 = row2['destinationip']
                        sourceip04 = row2['sourceip']

                        if((destinationport03 == sourceport04) and (sourceport03 == destinationport04) and (sourceip03 == destinationip04) and (destinationip03 ==sourceip04)and(protocol04 == protocol03)):
                                count = count + 1
                                Test_Data = Test_Data.drop([index1])
                                break

        duration_list = []
        packet_list = []
        bytes_list = []
        for index1, row in Test_Data.iterrows():
                count = 0
                j = 0
                temp = pd.DataFrame(columns=['protocol','sourceip','destinationip','sourceport','destinationport','captime','bytes'], index=[])
                protocol01 = row['protocol']
                sourceport01 = row['sourceport']
                destinationport01 = row['destinationport']
                sourceip01 = row['sourceip']
                destinationip01 = row['destinationip']
                for index, row in Live_Data.iterrows():
                        protocol02 = row['protocol']
                        sourceport02 = row['sourceport']
                        destinationport02 = row['destinationport']
                        sourceip02 = row['sourceip']
                        destinationip02 = row['destinationip']
                        if((protocol01 == protocol02) and (sourceport01 == sourceport02) and (destinationport01 == destinationport02) and (sourceip01 == sourceip02) and (destinationip01== destinationip02)):
                                count = count + 1
                                temp.loc[j] = pd.Series({'protocol':protocol02, 'sourceport':sourceport02, 'destinationport':destinationport02, 'sourceip':sourceip02, 'destinationip':destinationip02})
                                j=j+1
                Total = temp['bytes'].sum()
                Total1 = temp['captime'].max() - temp['captime'].min()
                dur_time = Total1/np.timedelta64(1,'s')
                int_dur = float(dur_time)
                duration_list.append(int_dur)
                bytes_list.append(Total)
                packet_list.append(count)
        Test_Data['duration'] = duration_list
        Test_Data['bytes'] = bytes_list
        Test_Data['packets'] = packet_list

        return(Test_Data)
        
def normalization(Live_Data, X_train,Test_Data):
        X_test =Test_Data[['duration','sourceport','destinationport','protocol','bytes','packets']]
        X_result = pd.DataFrame()
        X_result = Test_Data.copy(deep=True)
        X_result = X_result.reset_index(drop=True)
        X_test.rename(columns=lambda x: x.strip(),inplace=True)
        X_train['duration'] = X_train['duration']/ np.timedelta64(1,'s')
        #X_train['duration'] = X_train['duration'].astype(int)
        X_test['captime'] = X_test['duration']/ np.timedelta64(1,'s')
        #X_test['duration'] = X_test['duration'].astype(int)
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
                Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col].value_counts().index])
                Proto=Proto.set_index(X_train.index.values)
                X_train = X_train.drop(col, axis = 1)
                X_train=pd.concat([X_train,Proto],axis=1)
                Proto = enc.transform(X_test[[col]])
                Proto=pd.DataFrame(Proto,columns=[(col+"_"+str(i)) for i in data[col].value_counts().index])
                Proto=Proto.set_index(X_test.index.values)
                X_test = X_test.drop(col, axis = 1)
                X_test=pd.concat([X_test,Proto],axis=1)

        return(X_test,X_train, X_result )
# Implementing SVM model to train the model
def training(X_result,X_test,X_train,Y_train):
        from sklearn.svm import SVC
        clf = SVC()
        clf.fit(X_train, Y_train)
        SVC(C=1.0, cache_size=100, class_weight=None, coef0=1.0,
                decision_function_shape='ovr', degree=3, gamma=1, kernel='poly',
                max_iter=-1, probability=True, random_state=10, shrinking=False,
                tol=0.001, verbose=False)
        predict_out = clf.predict(X_test)
        Prediction = pd.DataFrame()
        Prediction[['label']] = pd.DataFrame(data=predict_out)
        # Trackig the bot IPs
        X_result = X_result.join(Prediction)
        Bots = pd.DataFrame()
        return(Bots)
#Insert the the bot data into traning table
def insert_bot_data():

        X_train, Y_train, Live_Data, conn = database()
        Test_Data = processing(Live_Data)
        X_test,X_train, X_result = normalization(Live_Data, X_train,Test_Data)
        Bots = training(X_result,X_test,X_train,Y_train)
        bot_mac = []
        for index, row in Bots.iterrows():
                m = str(row['sourcemac'])
                bot_mac.append(m)
                cur = conn.cursor()
                query = "INSERT INTO TrainingData (duration, protocol, service, sourceip,sourcemac,sourceport, destinationip,destinationmac,destinationport, tos, bytes,packets, label) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                args = (row['duration'], row['protocol'],row['service'],row['sourceip'],row['sourcemac'],row['sourceport'],row['destinationip'],row['destinationmac'],row['destinationport'],row['tos'],row['bytes'],row['packets'],row[0])
                cur.execute(query, args)
                conn.commit()
        return(list(set(bot_mac)))


