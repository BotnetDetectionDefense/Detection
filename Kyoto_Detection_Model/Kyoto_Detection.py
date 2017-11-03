# -*- coding: utf-8 -*-
"""
Created on Fri Oct  1 16:15:41 2017

@author: Pallak
"""

import numpy as np
import pandas as pd

# Importing training data set

X_train=pd.read_excel('X_train.xlsx')
Y_train=pd.read_excel('Y_train.xlsx')
Src_Dest_Port_IP = pd.read_excel('Src_Dest_Port_IP.xlsx')

# Importing test dataset

X_test=pd.read_excel('X_test.xlsx')

# Label encoding the data

from sklearn.preprocessing import LabelEncoder
le=LabelEncoder()
column = ['Service', 'Flag']
for col in column:
    if X_test[col].dtypes=='object':
        data=X_train[col].append(X_test[col])
        le.fit(data.values)
        X_train[col]=le.transform(X_train[col])
        X_test[col]=le.transform(X_test[col])

# One hot encoding of the label encoded data
        
from sklearn.preprocessing import OneHotEncoder
enc=OneHotEncoder(sparse=False)
columns=['Service', 'Flag']
for col in columns:

   

   data=X_train[[col]].append(X_test[[col]])
   enc.fit(data)
   Flag = enc.transform(X_train[[col]])
   Flag= pd.DataFrame(Flag,columns=[(col+"_"+str(i)) for i in data[col]
        .value_counts().index])
   Flag=Flag.set_index(X_train.index.values)
   X_train = X_train.drop(col, axis = 1)
   X_train=pd.concat([X_train,Flag],axis=1)
   Flag = enc.transform(X_test[[col]])
   Flag=pd.DataFrame(Flag,columns=[(col+"_"+str(i)) for i in data[col]
        .value_counts().index])
   Flag=Flag.set_index(X_test.index.values)
   X_test = X_test.drop(col, axis = 1)
   X_test=pd.concat([X_test,Flag],axis=1)


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

#  print(predict_out)


# Tracking the malicious IPs

Prediction = Src_Dest_Port_IP.join(predict_out)
Malicious = pd.DataFrame()
Malicious = Prediction[Prediction[0] == 0]
Malicious_IP = Malicious.drop_duplicates(subset=None, keep='first', inplace=False)

# Import result to excel

writer = pd.ExcelWriter('Result.xlsx')
predict_out.to_excel(writer,'Sheet1')
writer.save()