import json
import random
import socket
import select
import RsaManager
import AesManager
from CertificatesManager import CertificateManager

MERCHANT_PORT = 2004
BANK_PORT = 2005
HOST = '127.0.0.1'


class Client:
    def __init__(self, card_number, card_exp_date, amount):
        self.merchant_socket = socket.socket()
        self.merchant_host = HOST
        self.merchant_port = MERCHANT_PORT
        self.bank_socket = socket.socket()
        self.bank_host = HOST
        self.bank_port = BANK_PORT

        self.public_key, self.private_key = RsaManager.generate_keys(2048)
        self.merchant_public_key = None
        self.bank_public_key = None
        self.validate_certificates()
        self.merchant_aes_key = AesManager.generate_key()
        self.bank_aes_key = AesManager.generate_key()
        self.card_number = card_number
        self.card_exp_date = card_exp_date
        self.ccode = None
        self.amount = amount
        self.sid = None
        self.nc = None

    def validate_certificates(self):
        certMan = CertificateManager()
        if not certMan.validate_certificate('merchant_info/certificate.pem'):
            print("Invalid Merchant Certificate!")
            exit()
        print("Valid Merchant Certificate!")
        if not certMan.validate_certificate('bank_info/certificate.pem'):
            print("Invalid Bank Certificate!")
            exit()
        print("Valid Bank Certificate!")
        with open('merchant_info/public_key.pem', 'r') as f:
            self.merchant_public_key = f.read()
        with open('bank_info/public_key.pem', 'r') as f:
            self.bank_public_key = f.read()

    def run(self):
        self.connect_to_merchant()
        self.setup_sub_protocol()
        return self.exchange_protocol()

    def send_otp(self):
        self.connect_to_bank()
        message_to_encrypt = {
            "card_number": self.card_number,
            "card_exp_date": self.card_exp_date
        }
        new_bank_aes_key = AesManager.generate_key()
        enc_message_content = AesManager.encrypt(json.dumps(message_to_encrypt), new_bank_aes_key)
        enc_aes_key = RsaManager.encrypt(new_bank_aes_key, self.bank_public_key)

        message_content = {
            "enc_message_content": enc_message_content,
            "enc_aes_key": enc_aes_key
        }

        message_to_send = {
            'identifier': 'C_OTP',
            'message': message_content
        }
        self.bank_socket.send(json.dumps(message_to_send).encode())

        received = self.bank_socket.recv(4096)
        message_from_bank = AesManager.decrypt(received, new_bank_aes_key)
        self.bank_socket.close()
        return message_from_bank

    def connect_to_merchant(self):
        try:
            self.merchant_socket.connect((self.merchant_host, self.merchant_port))
        except socket.error as e:
            print(str(e))

    def connect_to_bank(self):
        try:
            self.bank_socket.connect((self.bank_host, self.bank_port))
        except socket.error as e:
            print(str(e))

    def setup_sub_protocol(self):
        enc_pub_key = AesManager.encrypt(self.public_key, self.merchant_aes_key)
        enc_aes_key = RsaManager.encrypt(self.merchant_aes_key, self.merchant_public_key)
        message_to_send = {
            "enc_pub_key": enc_pub_key,
            "enc_aes_key": enc_aes_key
        }
        self.merchant_socket.send(json.dumps(message_to_send).encode())
        received = self.merchant_socket.recv(1024)
        decrypted = AesManager.decrypt(received, self.merchant_aes_key)
        data = json.loads(decrypted)
        self.sid = data["sid"]
        signature = data["signature"]
        if not RsaManager.verify_signature(self.sid, signature, self.merchant_public_key):
            raise Exception("Setup Sub-Protocol Error: Invalid Merchant Message signature!")

    def exchange_protocol(self):
        self.nc = str(random.randint(1000, 9999))
        pm_info = {
            "card_number": self.card_number,
            "card_exp_date": self.card_exp_date,
            "ccode": self.ccode,
            "amount": self.amount,
            "sid": self.sid,
            "client_pk": self.public_key,
            "nc": self.nc,
            "merchant_identity": self.merchant_host + ":" + str(self.merchant_port)
        }
        pm = {
            "pm_info": pm_info,
            "signature": RsaManager.sign(RsaManager.trans_dict_to_hash(pm_info), self.private_key)
        }

        enc_pm = AesManager.encrypt(json.dumps(pm), self.bank_aes_key)
        enc_aes_key = RsaManager.encrypt(self.bank_aes_key, self.bank_public_key)

        po_info = {
            "order_desc": "This is the.",
            "sid": self.sid,
            "amount": self.amount,
            "nc": self.nc
        }
        po = {
            "po_info": po_info,
            "signature": RsaManager.sign(RsaManager.trans_dict_to_hash(po_info), self.private_key)
        }

        message_to_send = {
            "pm": {
                "enc_pm": enc_pm,
                "enc_aes_key": enc_aes_key
            },
            "po": po
        }

        message_to_send = AesManager.encrypt(json.dumps(message_to_send), self.merchant_aes_key)
        self.merchant_socket.send(message_to_send.encode())
        readable, _, _ = select.select([self.merchant_socket], [], [], 5)
        if self.merchant_socket in readable:
            res = self.merchant_socket.recv(4096)
        else:
            print('Timeout expired')
            self.merchant_socket.close()
            return self.resolution_sub_protocol()
        res = AesManager.decrypt(res, self.merchant_aes_key)
        message_from_bank = json.loads(res)

        message_to_verify = {
            "response": message_from_bank["response"],
            "sid": message_from_bank['sid'],
            "amount": po['po_info']['amount'],
            "nc": po['po_info']['nc']
        }

        if not RsaManager.verify_signature(RsaManager.trans_dict_to_hash(message_to_verify),
                                           message_from_bank["signature"], self.bank_public_key):
            raise Exception("Exchange Sub-Protocol Error: Invalid Bank Message signature!")

        self.merchant_socket.close()
        print(message_to_verify['response'])
        return message_to_verify['response']

    def resolution_sub_protocol(self):
        self.bank_socket = socket.socket()
        self.connect_to_bank()

        message_to_sign = {
            "sid": self.sid,
            "amount": self.amount,
            "nc": self.nc,
            "pk": self.public_key
        }

        signature = RsaManager.sign(json.dumps(message_to_sign), self.private_key)

        message_to_encrypt = {
            "message": message_to_sign,
            "signature": signature
        }
        new_bank_aes_key = AesManager.generate_key()
        enc_message_content = AesManager.encrypt(json.dumps(message_to_encrypt), new_bank_aes_key)
        enc_aes_key = RsaManager.encrypt(new_bank_aes_key, self.bank_public_key)

        message_content = {
            "enc_message_content": enc_message_content,
            "enc_aes_key": enc_aes_key
        }

        message_to_send = {
            'identifier': 'C',
            'message': message_content
        }
        self.bank_socket.send(json.dumps(message_to_send).encode())

        received = self.bank_socket.recv(4096)
        message_from_bank = AesManager.decrypt(received, new_bank_aes_key)
        message_from_bank = json.loads(message_from_bank)

        message_to_verify = {
            "response": message_from_bank["response"],
            "sid": message_from_bank['sid'],
            "amount": message_to_sign["amount"],
            "nc": message_to_sign["nc"]
        }

        if not RsaManager.verify_signature(RsaManager.trans_dict_to_hash(message_to_verify),
                                           message_from_bank["signature"], self.bank_public_key):
            raise Exception("Resolution Sub-Protocol Error: Invalid Bank Message signature!")

        print(message_to_verify['response'])
        return message_to_verify['response']
