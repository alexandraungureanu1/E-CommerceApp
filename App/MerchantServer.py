import base64
import json
import random
import socket
from _thread import *
import time

import AesManager
import RsaManager
from CertificatesManager import CertificateManager


class MerchantServer:
    def __init__(self):
        self.ServerSideSocket = socket.socket()
        self.host = '127.0.0.1'
        self.port = 2004
        self.threadCount = 0
        with open('merchant_info/public_key.pem', 'r') as f:
            self.public_key = f.read()
        with open('merchant_info/private_key.pem', 'r') as f:
            self.private_key = f.read()
        self.bank_public_key = None

        self.validate_certificates()

        self.client_aes_key = None
        self.bank_aes_key = AesManager.generate_key()
        self.client_public_key = None
        try:
            self.ServerSideSocket.bind((self.host, self.port))
        except socket.error as e:
            print(str(e))
        print('[Merchant]: Merchant is running...')
        self.ServerSideSocket.listen(5)

    def validate_certificates(self):
        certMan = CertificateManager()
        if not certMan.validate_certificate('bank_info/certificate.pem'):
            print("Invalid Bank Certificate!")
            exit()
        print("Valid Bank Certificate!")
        with open('bank_info/public_key.pem', 'r') as f:
            self.bank_public_key = f.read()

    # Thread for each client
    def multi_threaded_client(self, connection):
        self.setup_sub_protocol(connection)
        self.exchange_sub_protocol(connection)

    # STEPS 3 ---> 6
    def exchange_sub_protocol(self, connection):
        data = connection.recv(4096)  # message received from client
        # establish connection to bank and get message
        data = data.decode()
        data = AesManager.decrypt(data, self.client_aes_key)
        data = json.loads(data)
        pm = data['pm']
        po = data['po']
        message_to_sign = {
            "sid": po['po_info']['sid'],
            "amount": po['po_info']['amount'],
            "client_pk": self.client_public_key
        }

        signature = RsaManager.sign(RsaManager.trans_dict_to_hash(message_to_sign), self.private_key)
        message_content = {
            "pm": pm,
            "signature": signature
        }
        enc_message_content = AesManager.encrypt(json.dumps(message_content), self.bank_aes_key)
        enc_aes_key = RsaManager.encrypt(self.bank_aes_key, self.bank_public_key)

        message_to_bank = {
            "enc_message_content": enc_message_content,
            "enc_aes_key": enc_aes_key
        }

        message_to_send = {
            'identifier': 'M',
            'message': message_to_bank
        }
        message_to_bank = json.dumps(message_to_send).encode()
        message_from_bank = self.connect_to_bank(message_to_bank)
        message_from_bank = AesManager.decrypt(message_from_bank, self.bank_aes_key)  # decrypted message
        message_from_bank = json.loads(message_from_bank)

        message_to_verify = {
            "response": message_from_bank["response"],
            "sid": message_from_bank['sid'],
            "amount": po['po_info']['amount'],
            "nc": po['po_info']['nc']
        }

        if not RsaManager.verify_signature(RsaManager.trans_dict_to_hash(message_to_verify),
                                           message_from_bank["signature"], self.bank_public_key):
            raise Exception("Exchange Sub-Protocol Error: Invalid Bank Message signature!")

        response_to_client = AesManager.encrypt(json.dumps(message_from_bank), self.client_aes_key)

        # time.sleep(10)
        connection.sendall(response_to_client.encode())
        connection.close()

    # STEPS 1 & 2
    def setup_sub_protocol(self, connection):
        data = connection.recv(2048)  # receive data from client
        print('[Merchant]: message received from client.')
        data = json.loads(data)
        enc_aes_key = data["enc_aes_key"]
        enc_pub_key = data["enc_pub_key"]
        dec_aes_key = RsaManager.decrypt(enc_aes_key, self.private_key)
        dec_pub_key = AesManager.decrypt(enc_pub_key, dec_aes_key)
        self.client_aes_key = dec_aes_key
        self.client_public_key = dec_pub_key

        sid = str(random.randint(1000, 9999))
        signature = RsaManager.sign(sid, self.private_key)

        response = {
            "sid": sid,
            "signature": signature
        }
        encrypted_response = AesManager.encrypt(json.dumps(response), self.client_aes_key)
        connection.sendall(encrypted_response.encode())
        print('[Merchant]: message sent to client.')

    # STEPS 4 & 5
    def connect_to_bank(self, data_to_send):
        merchant_socket = socket.socket()
        bank_host = '127.0.0.1'
        bank_port = 2005

        # connect merchant to bank
        try:
            merchant_socket.connect((bank_host, bank_port))
        except socket.error as e:
            print(str(e))

        # send message to bank
        merchant_socket.send(data_to_send)

        # receive message from bank
        res = merchant_socket.recv(4096)
        merchant_socket.close()

        return res

    def start_server(self):
        while True:
            Client, address = self.ServerSideSocket.accept()
            print('[Merchant] Connected to: ' + address[0] + ':' + str(address[1]))
            start_new_thread(self.multi_threaded_client, (Client,))
            self.threadCount += 1
            print('[Merchant] Thread Number: ' + str(self.threadCount))
        # ServerSideSocket.close()


if __name__ == "__main__":
    MerchantServer().start_server()
