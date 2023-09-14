# Securing Wireless Networks 

# Author
Jiajin Chen; Haowen Zhao

# Detecting and Predicting Hand Gestures from RSS

The project's objective is to detect and predict the hand gestures through the change of RSS. RSS refers to the received signal strength, which is commonly used to detect 
the wifi signal strength. To obtain the data, the laptop was connected to the mobile's hotspot, and then I ping the PC's network to the hotspot's IP address with 100ms per packet to get more data packets. WireShark was used to capture all the data, filtered by my student id. The captured data was then pre-processed and trained in Python through SVM ML Algoritm. A classification report was used to evaluate the model. 


## Description

### Gesture Design 
I designed 3 different gestures: Swipe, Cover, and Clock-wise circles. For each of the gesture, one movement consisted of 4 seconds, and I performed 30 times for each gesture, so in all there would be 30 different files for each gesture. For 1 file, 30 packets were used to implement the model, so in all, there were 900 packets for one gesture. Another dataset with 30 times of gesture movements in one file for each of them was also created to demonstrate in the graph to compare the change of the RSS. 

### Spacial set up
To collect the data, i put my phone and laptop 2 meters apart from each other in the same room, and there was no obstacle in between so LoS was satisfied, and both of them were placed on 2 chairs with the same height. 

### Data Collection
I connected the device to my mobile hotspot, and ping the internet with 100ms per packet, so that i can receive more data. 
The following command was used in the terminal to ping the ip address of 170.20.10.1
```bash
ping - 0.1 170.20.10.1
```

I then sat beside my phone, performed the gestures and collected the data through Wireshark. after the data is collected, i stored them into my pc for the future use. 

### Chosen Algorithn
SVM machine learning algorithm was chosen to train and predicted the data. This is a good classification model by applying hyperplanes to the dataset for my dataset with a high accuracy of 72%. 


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
