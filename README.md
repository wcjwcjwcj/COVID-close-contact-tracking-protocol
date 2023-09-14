![image](https://github.com/wcjwcjwcj/security-project/assets/86811146/86a79d71-8ab4-4919-bfc9-c9981b0ca53e)# COVID Tracking Protocol: DIMY 'Did I Meet You'


# Author
Jiajin Chen
# Video Demo Link:
https://youtu.be/qa1j_49xxtY

# Executive Summary:

The DIMY hybrid digital contact tracing protocol aims to trace close contact of someone who got diagnosed with COVID-19 and alarm those who could be under the risk of infection. There are several salient features of the protocol implementation that we would like to emphasize. 
We implemented Dimy.py, DimySever.py and Attacker.py for the purpose of building connection between clients, storing all close contact information to the backend server, and testing the security of protocol. 
For Dimy.py, we firstly built connection between clients via UDP and generated a random 16-byte ID for each client. This could be broadcasted via splitting to 5 shares by Shamir Secret Sharing mechanism. The mechanism allows the safety identification process as a specific number of shares are required to identify the client. We then implemented Diffie-Hellman Key Exchange mechanism to build encounter ID, this further ensures the safety identification as shared secret are built between the 2 users. Information of Encounter ID of 90 seconds (for demonstration purpose) are stored in Daily Bloom Filter, and this would be further stored in Query Bloom Filter. The feature of Query Bloom Filter (QBF) allows the protocol to store the information of people they have close contact with. 
Meanwhile, DimyServer.py for the TCP connection from client to backend server is built. This allows a user to update their close contact to the server when he or she catches COVID, all users’ DBF with COVID positive would be combined into a Contact Bloom Filter (CBF) and sent to our backend server, so when there are multiple patients, all close contact can be stored. The feature also allows the comparison between uploaded QBF by a user and the CBF of Covid patients, so that if they match, the users can be recognized as close contact of Covid, and information would be notified to them.
Finally, Attacker.py is used to test the security of the protocol. We implemented TCP/UDP flood DoS attack to send a high volume of traffic to the system. We identified the potential threat of UDP/TCP connection from flood attack and further security measures was recommended.


## Implementation Details:

In this part, we will give out a list of features that the protocol has successfully achieved following the tasks details.

Step 1: We generated a 16-byte Ephemeral ID every 15 seconds. We imported the ecdsa library from Python to get the private and public key which utilizes the Elliptic Curve Cryptography. The curve we chose was SECP128r1. This algorithm allows users to generate keys following a certain function (defined by curve) and the generated public key was used as EphID for our users. Once generated, it would wait for 15 seconds till generating the next key.

Step 2: We used Shamir key exchange algorithm from Crypto.Protocol.SecretSharing library. This allows us to broadcast the EphID from task 1 by splitting to 5 shares to clients, and the shared secret can be rebuilt once 3 shares are received out of 5.

Step 3 and 3a: We used UDP broadcasting feature to advertise our 5 shares for each EphID following the frequency of 3 seconds per share. So, 15 seconds would be used to broadcast all shares. We also considered the situation of lost connection; hence a 50% probability of message dropping rate was implemented. 

Step 4: If a user receives at least 3 shares from the same EphID, that means the shared secret was successfully built. We verified the EphID by comparing the advertised hash from the client and the rebuilt hash by the 3 shares received. 

Step 5: The encounter ID is then built through Diffie-Hellman Key Exchange Mechanism. We used Python library ecdh from ecdsa to generate shared secret between 2 users, the shared secret is used as Encounter ID.

Step 6: Encounter ID is encoded by hashing 3 times and then stored into the Daily Bloom Filter (DBF) built via Bloom Filter Class in the code. We referenced online resource for the Bloom Filter Class part and the reference link is given in the code. The encounter ID is then deleted.

Step 7 & 8:  A new DBF is produced every 90 second for demonstration purpose and stored in a node with a maximum number of 6 DBFs. Every 9 minutes, all nodes of DBFs would be stored in QBF then deleted. 

Step 9: QBF generated would be sent to the backend server via TCP. The server would perform scanning for QBF and Covid patients’ CBF to get the result of close contact which would be displayed to the clients. This feature allows the system to detect the potential close contacts of Covid patients and notify people in a timely manner.

Step 10: A client who caught Covid can would have a CBF which contains all information of their DBF, and they can upload their CBF to the backend server. After that, it will stop producing QBF. 

Step 11: We implemented TCP/UDP flood DoS attack to send a high volume of traffic to system. We reset the time interval of sending shares from 3 seconds to 0. This means a node will receive many shares and the bit index of 0 will be destructively occupied by 1. If a node. As a result, if a node uploads its QBF, the false probability being a close contact of Covid patients would be dramatically increased. Furthermore, it cannot control/examine the network traffic and eventually take up too much memory/traffic, the system would crash. The suggestion we must prevent this attack is to set threshold for the allowed volume of packets each second, so when the volumes become abnormal the system can detect the attack and drop the packets. 


### Design Trade-offs

To achieve synchronize in a timely manner, we used UDP connection. However, it does have a drawback as it must have well-known ports of clients to be able to broadcast over a socket. Another drawback is that when there are a lot of users, UDP does not have any congestion control check nor connection establishment process. The reliability of transmitting data and the congested traffic when there are multiple users could be potential issues of the protocol using UDP. More advanced technologies should be considered. 
We sent our data with 100KB size using Bitarray library from Python, which could take up too much memory. While there could be a lot of QBF, CBF being uploaded and stored, they could take a lot of space, and be computationally complex. A better way or format of storing the data should be considered. 

### Borrowed Code:

We referenced the code from https://github.com/jaybaird/python-bloomfilter to build our Bloom Filter class to encode Encounter ID.


## Getting Started

### Programming language
* Python 3
* Version: 3

### Dependencies: Libraries to use 

* pandas
* math
* matplotlib.pyplo
* numpy 
* sklearn
* preprocessing
* sklearn.preprocessing
* MinMaxScaler
* sys
* sklearn.metrics
* precision_recall_fscore_support, accuracy_score,classification_report
* re
* sklearn.model_selection
* train_test_split
* svm
* sklearn.svm
* SVR
* seaborn
*  r2_score,mean_squared_error

### Installing

* The code files are zipped in a file called 'code'
*  unzipped the file to get readme and code files 
*  2 code files are inside, one is 'final.ipynb' to demonstrate my result, one is 'final.py' to execute the code 
* Download the source code 'final.py' file
* All the datasets are in an zipped file: 'data.zip'
* Unzip all the files, and put all the data files under the same folder of the python file. 
* 'p*.csv' files stand for cover gesuture; 'h*.csv' file stands for circle gestures; 'u*.csv' files stand for swipe gesture; there are 30 files for each gesture.
* '30swipe.csv', '30cover.csv', '30circle.csv' are used to visualise and demonstrate the changing RSS over gestures. 
* Video Presentation is under the 'presentation' file 

### Executing program

* import libraries

```python
import pandas as pd
import math
import matplotlib.pyplot as plt
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import sys
from sklearn.metrics import precision_recall_fscore_support, accuracy_score,classification_report
import re
from sklearn.model_selection import train_test_split
from sklearn.svm import SVR
from sklearn.metrics import r2_score,mean_squared_error
import seaborn as sns
import sklearn
from sklearn import preprocessing
from sklearn import svm

```

* use lable decoder to transform the different gestures to 0,1,2
```python
# use lable decoder to transform the different gestures to 0,1,2
le = preprocessing.LabelEncoder()
```

* Define a function to read the file and get the data 

```python
def r(file):
    selected = pd.read_csv(file)
 
    x = selected.iloc[:,6:7].values
    x1=[]
    for i in x:
        c = int(i[0][:-3])
        x1.append(c)


    return x1
```
* Read 3 gestures and create panda dataframes 
```python
# read and create dataframe for cover gesture
x11 = []
y1=[]
for i in range(1,31):
    x = r(f'p{i}.csv')
    
    x1 = x[:30]  
    x1.append('cover')
    x11.append(x1)
df = pd.DataFrame(x11, columns =['0','1', '2', '3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','Gesture'], dtype = float)

# read and create dataframe for circle gesture
x22 = []
y2=[]
for i in range(1,31):
    a = r(f'h{i}.csv')
    x2 = a[:30]  
    x2.append('circle')
    x22.append(x2)
df2 = pd.DataFrame(x22, columns =['0','1', '2', '3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','Gesture'], dtype = float)

# read and create dataframe for swipe gesture
x33 = []
y3=[]
for i in range(1,31):
    a = r(f'u{i}.csv')
    x3 = a[:30]  
    x3.append('Swipe')
    x33.append(x3)
df3 = pd.DataFrame(x33, columns =['0','1', '2', '3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','Gesture'], dtype = float)
```

* Combined all the data to one dataframe 
```python
result = df.append(df2, ignore_index=True)
final = result.append(df3,ignore_index =True)
```


* export training and test datasets to csv

```python
# export training and test to csv
training = final[:72]
test = final[72:]
training.to_csv('training.csv')
test.to_csv('test.csv')
```

*  Since i have the file, i will directly use the overall file from 'final',Select the data and transform the lable to 0,1,2 by encoding 
```python
x= final.iloc[:,:-1]
y= final.loc[:,'Gesture']
y =le.fit(y)

x= final.iloc[:,:-1]
y= final.loc[:,'Gesture']
yenc = le.transform(y)
final['Gesture']=yenc

x= final.iloc[:,:-1]
y= final.loc[:,'Gesture']
```

* Use the MinMaxScaler to standardesed the data, then split the data to 80% of training and 20% of test data

```python
x1 = x.values 
min_max_scaler = preprocessing.MinMaxScaler()
x_scaled = min_max_scaler.fit_transform(x1)
sdx = pd.DataFrame(x_scaled)
trainx,testx,trainy,testy = train_test_split(sdx,y,train_size = 0.8)
trainx1 = trainx.values

```

* Create a svm Classifier, Predict the response for test dataset
```python
clf = svm.SVC(kernel='linear') 
clf.fit(trainx,trainy)

#Predict the response for test dataset
predicty = clf.predict(testx)
```

* Get the classification report and export to csv to predict the data
```python
print(classification_report(testy,predicty))
```

* print out the Prediction for test dataset
```python
#print out the Prediction for test dataset
print(predicty)
```

* to demonstrate and visualise the data, i visualised the RSS change over gestures from one file, where i collected the rss over 30 times of each gestures movement 
```python
# for swipe 
swipe = pd.read_csv('30swipe.csv')
selected = swipe[['Time','Signal strength (dBm)']]
x = selected['Signal strength (dBm)']
for i in range(0,len(x)):
    c = int(x[i][:-3])
    x[i] = c
plt.figure(figsize=(20, 8))

plt.title('Swipe Signal Strength')
plt.xlabel('Time')
plt.ylabel('Signal Strength')
x= selected['Time']
y = selected['Signal strength (dBm)']
plt.plot(x, y,linewidth=2)
plt.show()


# for cover
cover = pd.read_csv('30cover.csv')
selected = cover[['Time','Signal strength (dBm)']]
x = selected['Signal strength (dBm)']
for i in range(0,len(x)):
    c = int(x[i][:-3])
    x[i] = c
plt.figure(figsize=(20, 8))

plt.title('Cover Signal Strength')
plt.xlabel('Time')
plt.ylabel('Signal Strength')
x= selected['Time']
y = selected['Signal strength (dBm)']
plt.plot(x, y,linewidth=2)
plt.show()


# for circle 
circle = pd.read_csv('30circle.csv')
selected = circle[['Time','Signal strength (dBm)']]
x = selected['Signal strength (dBm)']
for i in range(0,len(x)):
    c = int(x[i][:-3])
    x[i] = c
plt.figure(figsize=(20, 8))

plt.title('Circle Signal Strength')
plt.xlabel('Time')
plt.ylabel('Signal Strength')
x= selected['Time']
y = selected['Signal strength (dBm)']
plt.plot(x, y,linewidth=2)
plt.show()
```

## Author

Jiajin Chen; 
