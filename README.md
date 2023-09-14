# COVID Tracking Protocol: DIMY 'Did I Meet You'


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

