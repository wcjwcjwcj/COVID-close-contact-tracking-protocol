import socket
import threading
import re
import bitarray


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen(10)
        self.qbfs = []
        self.cbfs = []

    def recv(self, client, address):
        msg = client.recv(102500).decode()
        sym, bit = msg.split('@', 1)

        if sym == 'q':
            qbf = [int(i) for i in bit.split('@')]
            self.qbfs.append(qbf)
            print(sym, 'This means receive QBF.')
            print('Task9: Receive QBF from ', address)
            # find1 = re.finditer('1', bit)
            # output = []
            # for i in find1:
            #     j = i.start(0)
            #     output.append(j)
            # print(f"QBF: {output}")

            if not self.cbfs:
                # print("There is no one being covid.")
                client.send("There is no one being covid.".encode())
            else:

                for cbf in self.cbfs:
                    share = 0
                    for i in qbf:
                        if i in cbf:
                            share += 1
                    if share >= 3:
                        client.send("You are one of close contacts to covid.".encode())
                        break
                    else:
                        continue
                else:
                    # print("You are one of close contacts to covid.")

                    # print("You are not close to covid.")
                    client.send("You are not close to covid.".encode())
        elif sym == 'c':
            cbf = [int(i) for i in bit.split('@')]
            self.cbfs.append(cbf)
            print('-'*20)
            print(sym, 'This means receive CBF.')
            print('Task10: Receive CBF from ', address)
            print('-'*20)
            # find1 = re.finditer('1', bit)
            # output = []
            # for i in find1:
            #     j = i.start(0)
            #     output.append(j)
            # print(f"CBF: {output}")
            meet = []
            # for qbf in self.qbfs:
            #     c = bitarray.bitarray(bit) & bitarray.bitarray(qbf[0])
            #     if c.count(1) >= 3:
            #         meet.append(qbf[1])
            # print('Find meet close person:')
            # for i in meet:
            #     print(i)
            client.send('Server has received CBF.'.encode())

    def start(self):
        while True:
            # print('Listen for client...')
            client, address = self.socket.accept()
            print(f"{address} has connected.")
            recv = threading.Thread(target=self.recv, args=(client, address))
            recv.start()


if __name__ == '__main__':
    server = Server('192.168.1.100', 55000)
    server.start()