#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#####################################################################
# !/usr/bin/env python
# coding: utf-8

# In[1]:
import json
import socket
import random
from Crypto.Protocol.SecretSharing import Shamir
import threading
import sys
import time
from ecdsa import ECDH, SigningKey, SECP128r1
import re
from binascii import unhexlify, hexlify
from time import sleep
from hashlib import sha256
import mmh3
from copy import deepcopy
import bitarray

pn = 38871  # portnumber

# We referenced Bloom Filter class below from the website.
# Reference link: https://github.com/jaybaird/python-bloomfilter
class BloomFilter:
    def __init__(self, filter_size, seeds):
        self.filter_size = filter_size
        self.bit_array = bitarray.bitarray(self.filter_size)
        self.bit_array.setall(0)
        self.seeds = seeds

    def __len__(self):
        return self.filter_size

    def __iter__(self):
        return iter(self.bit_array)

    def add(self, key):
        for seed in self.seeds:
            index = mmh3.hash(key, seed) % self.filter_size
            self.bit_array[index] = 1

    def reset(self):
        self.bit_array.setall(0)

    def dbf2qbf(self, dbfs):
        self.reset()
        for dbf in dbfs:
            self.bit_array |= dbf.bit_array

    def __contains__(self, item):
        output = True
        for seed in self.seeds:
            index = mmh3.hash(item, seed) % self.filter_size
            if self.bit_array[index] == 0:
                output = False
        return output

    def out(self):
        find1 = re.finditer('1', str(self.bit_array))
        output = []
        for i in find1:
            j = i.start(0)
            output.append(j)

        return output




class Node:
    def __init__(self, ip, port):
        self.ip = ip  # server tcp ip                  
        self.port = port  # server tcp port             
        # self.udpPort = udpPort                      
        self.ephId = None
        self.DBF = BloomFilter(800000, [13, 37, 61])
        self.DBF_list = []
        self.QBF = BloomFilter(800000, [13, 37, 61])
        self.CBF = BloomFilter(800000, [13, 37, 61])
        self.temp = {}                                
        self.sharelist = []                      
        self.hashlist = []                           
        self.share = 0  # initial share is 0          
        self.k = 3  # needs at least 3 shares
        self.n = 5  # seperate to 5 shares
        self.broadcasting_hash = None
        # self.tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.tcpSocket.connect((self.ip, self.port))    
        self.previoushash = []                          
        self.prikey = None                          
        self.ecdh = ECDH(curve=SECP128r1)
        self.covid = False

    def generate_id(self):
        # task1
        # generate id every 15 seconds
        self.ecdh.generate_private_key()
        ephid = (self.ecdh.get_public_key().to_string("compressed"))[1:17]
        self.ephId = ephid
        print(' '*100, '#'*70)
        print(' ' * 100, '#' * 70)
        print(' ' * 100, '#' * 70)
        print(' '*100, 'Task1: ephid is :', self.ephId)

        # time.sleep(15)

    def udp_send(self):
        # task 2 and 3: broadcast shares every 3 sec
        gs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        gs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        hasedid = sha256(self.ephId)

        broadcasting_hash = hasedid.hexdigest()
        self.broadcasting_hash = broadcasting_hash
        secretshares = Shamir.split(self.k, self.n, self.ephId)
        print('Task2:', secretshares)
        print('Task3:')

        for i in secretshares:
            index = str(i[0])
            data = hexlify(i[1]).decode()
            finalmessage = index + ',' + data + ',' + self.broadcasting_hash
            finalmessage = finalmessage.encode('utf-8')
            prob = random.random()
            if prob >= 0.5:
                gs.sendto(finalmessage, ('<broadcast>', pn))
                print(' '*130, 'success')
            else:
                print(' '*130, 'message dropped')
            sleep(3)

    def udp_receive(self):
        receiving = {}
        recSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        recSocket.bind(('', pn))
        self.DBF.reset()
        while not self.covid:
            msg, address = recSocket.recvfrom(2048)

            index, receiving_shares, receiving_hash = msg.decode('utf-8').split(',')
            receiving_shares = unhexlify(receiving_shares.encode())
            # print(111, index, receiving_shares, receiving_hash)
            # print(receiving_hash)
            # print(self.broadcasting_hash)
            if receiving_hash != self.broadcasting_hash:
                ################################### ！= #####

                if receiving_hash in receiving.keys() and (index, receiving_shares) not in receiving[receiving_hash]:
                    receiving[receiving_hash].append((int(index), receiving_shares))

                elif receiving_hash not in receiving.keys():
                    receiving[receiving_hash] = [(int(index), receiving_shares)]
                # print('receiving_shares:', receiving_shares)

                #
                if len(receiving[receiving_hash]) <= 3:
                    print('-' * 50)
                    print('receiving_hash:', receiving_hash)
                    print('receive shares counts:', len(receiving[receiving_hash]))

                self.previoushash.append(receiving_hash)

                # task 4 reconstruct id
                if len(receiving[receiving_hash]) == self.k:
                    # print(receiving[receiving_hash])
                    secret = Shamir.combine(receiving[receiving_hash])
                    hashingkey = sha256(secret).hexdigest()
                    self.previoushash = []
                    print('Task5:')
                    print('hashed key is:', hashingkey)
                    print('receiving hashed eph is:', receiving_hash)

                    if hashingkey == receiving_hash:
                        print('Task6: key successully built, now building encounter id ')
                        # task 5, using df key exchange to get the encid
                        newkey = bytes(b"\x02") + secret
                        self.ecdh.load_received_public_key_bytes(newkey)
                        Enc_ID = self.ecdh.generate_sharedsecret_bytes()

                        print("ENCOUNTER ID FOUND!: ", Enc_ID)
                        # task6: encode encounter id and add to DBF then delete
                        self.DBF.add(Enc_ID)
                        # print(self.DBF.bit_array)
                        print('Task6: DBF built:', self.DBF.out())
                        del Enc_ID

    #
    # def dbf_update(self):
    #     self.DBF_list.append(self.DBF)
    #     self.DBF_list.pop(0)
    #     self.DBF.bit_array.setall(0)

    def dbf_update(self):
        # sleep(15)
        print('Task7: Update DBF to DBF List')
        if len(self.DBF_list) >= 6:
            self.DBF_list = self.DBF_list[1:]
        self.DBF_list.append(deepcopy(self.DBF))
        self.DBF.reset()

    def qbf_upload(self):
        # sleep(90)
        # if not self.covid:
        self.QBF.dbf2qbf(self.DBF_list)

        # task 8
        print(len(self.DBF_list))

        print('Task8: created QBF', self.QBF.out())
        print('Task9: Send QBF to Server via TCP...')
        ###
        bit = self.QBF.out()
        msg = ('q@' + '@'.join(str(i) for i in bit)).encode()
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.connect((self.ip, self.port))
        tcpSocket.send(msg)
        # recvmsg = tcpSocket.recv(1024).decode()
        # print(recvmsg)
        def recv():
            recvmsg = tcpSocket.recv(1024).decode()
            print(recvmsg)

        re = threading.Thread(target=recv)
        re.setDaemon(True)
        re.start()


    def cbf_upload(self):
        self.CBF.dbf2qbf(self.DBF_list)
        print(len(self.DBF_list))
        self.DBF_list = []
        print('-' * 50)
        print('TCP to the server with CBF...')
        bit = self.CBF.out()
        msg = ('c@' + '@'.join(str(i) for i in bit)).encode()
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.connect((self.ip, self.port))
        tcpSocket.send(msg)

        def recv():
            recvmsg = tcpSocket.recv(1024).decode()
            print(recvmsg)

        re = threading.Thread(target=recv)
        re.setDaemon(True)
        re.start()


    def has_covid(self):
        while True:
            a = input()
            if a == 'covid':
                self.covid = True
                self.cbf_upload()
                break



    def start(self):
        print('BROADCASTING...')

        recv = threading.Thread(target=self.udp_receive)
        recv.setDaemon(True)
        recv.start()

        covid = threading.Thread(target=self.has_covid)
        covid.setDaemon(True)
        covid.start()

        # dbf_update_ = threading.Thread(target=self.dbf_update)
        # dbf_update_.setDaemon(True)
        # dbf_update_.start()
        #
        # qbf_update_ = threading.Thread(target=self.qbf_upload)
        # qbf_update_.setDaemon(True)
        # qbf_update_.start()
        #
        # while True:
        #     self.generate_id()
        #     self.udp_send()



        while True:
            for i in range(6):
                for _ in range(6):
                    if not self.covid:
                        self.generate_id()
                        self.udp_send()
                if not self.covid:
                    self.dbf_update()
                    print('update dbf')
                    # sleep(1)
            if not self.covid:
                self.qbf_upload()
            else:
                break
        #     # time.sleep(5)


if __name__ == '__main__':
    # udpPort = sys.argv[1]
    client = Node('192.168.1.100', 55000)
    # client = Node('192.168.1.100', 5001, udpPort)
    client.start()










