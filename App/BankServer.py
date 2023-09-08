import json
import socket
from _thread import *
import RsaManager
import AesManager
import SmsManager
from CertificatesManager import CertificateManager


class BankServer:
    def __init__(self):
        self.ServerSideSocket = socket.socket()
        self.host = '127.0.0.1'
        self.port = 2005
        self.threadCount = 0
        try:
            self.ServerSideSocket.bind((self.host, self.port))
        except socket.error as e:
            print(str(e))
        print('[Bank]: Bank is running...')
        self.ServerSideSocket.listen(5)

        with open('bank_info/public_key.pem', 'r') as f:
            self.public_key = f.read()
        with open('bank_info/private_key.pem', 'r') as f:
            self.private_key = f.read()
        self.merchant_public_key = None

        self.validate_certificates()

        self.connection_aes_keys = dict()
        self.customer_service = CustomerService()

    def validate_certificates(self):
        certMan = CertificateManager()
        if not certMan.validate_certificate('merchant_info/certificate.pem'):
            print("Invalid Merchant Certificate!")
            exit()
        print("Valid Merchant Certificate!")
        with open('merchant_info/public_key.pem', 'r') as f:
            self.merchant_public_key = f.read()

    # STEPS 4 & 5
    def multi_threaded_client(self, connection):
        data = connection.recv(4096)

        data = json.loads(data)

        if data['identifier'] == 'C':
            self.resolution_sub_protocol(connection, data['message'])
            return
        elif data['identifier'] == 'C_OTP':
            self.send_otp(connection, data['message'])
            return

        data = data['message']
        dec_aes_key_merchant = RsaManager.decrypt(data["enc_aes_key"], self.private_key)
        dec_message_content = AesManager.decrypt(data["enc_message_content"], dec_aes_key_merchant)

        dec_message_content = json.loads(dec_message_content)
        pm = dec_message_content['pm']
        merchant_signature = dec_message_content['signature']

        dec_aes_key_client = RsaManager.decrypt(pm['enc_aes_key'], self.private_key)
        dec_message_content = AesManager.decrypt(pm['enc_pm'], dec_aes_key_client)

        pm = json.loads(dec_message_content)
        pm_info = pm["pm_info"]
        sig_pm_info = pm["signature"]
        client_pk = pm_info["client_pk"]

        if not RsaManager.verify_signature(RsaManager.trans_dict_to_hash(pm_info), sig_pm_info, client_pk):
            raise Exception("Exchange Sub-Protocol Error: Invalid Client PM signature!")

        message_to_verify = {
            "sid": pm_info["sid"],
            "amount": pm_info["amount"],
            "client_pk": pm_info["client_pk"]
        }

        if not RsaManager.verify_signature(RsaManager.trans_dict_to_hash(message_to_verify), merchant_signature,
                                           self.merchant_public_key):
            raise Exception("Exchange Sub-Protocol Error: Invalid Merchant Message signature!")

        response = self.check_customer_data(pm_info)

        message_to_sign = {
            "response": response,
            "sid": pm_info['sid'],
            "amount": pm_info['amount'],
            "nc": pm_info['nc']
        }
        signature = RsaManager.sign(RsaManager.trans_dict_to_hash(message_to_sign), self.private_key)

        response_to_merchant = {
            "response": response,
            "sid": pm_info['sid'],
            "signature": signature
        }
        response_to_merchant = AesManager.encrypt(json.dumps(response_to_merchant), dec_aes_key_merchant)
        connection.sendall(response_to_merchant.encode())
        connection.close()

    def check_customer_data(self, data):
        customer = self.customer_service.verify_customer(data)
        if customer is False:
            return "Abort: Customer not found"
        if not customer.verify_balance(data):
            self.customer_service.add_transaction(data, "Abort: Transaction failed, no money, poor guy.")
            return "Abort: Transaction failed, no money, poor guy"
        if self.customer_service.verify_transaction(data):
            self.customer_service.add_transaction(data, "Abort: Transaction not unique.")
            return "Abort: Transaction not unique."
        self.customer_service.add_transaction(data, "Transaction successfully accomplished.")
        customer.subtract_money(data)
        return "Transaction successfully accomplished."

    def verify_transaction_existence(self, data):
        trs = self.customer_service.verify_transaction(data)
        if trs is not False:
            return trs.status
        return "Abort: Transaction not found."

    def send_otp(self, connection, data):
        dec_aes_key_client = RsaManager.decrypt(data["enc_aes_key"], self.private_key)
        dec_message_content = AesManager.decrypt(data["enc_message_content"], dec_aes_key_client)
        dec_message_content = json.loads(dec_message_content)
        card_number = dec_message_content["card_number"]
        card_exp_date = dec_message_content["card_exp_date"]
        customer = self.customer_service.get_customer_by_card_number(card_number)
        if not customer or customer.card_exp_date != card_exp_date:
            response = "Invalid Card Info!"
        else:
            otp_code = SmsManager.send_otp(customer.phone_number)
            customer.ccode = otp_code
            response = "Verify your phone for the OTP Code!"

        response_to_client = AesManager.encrypt(response, dec_aes_key_client)
        connection.sendall(response_to_client.encode())
        connection.close()

    def resolution_sub_protocol(self, connection, data):
        dec_aes_key_client = RsaManager.decrypt(data["enc_aes_key"], self.private_key)
        dec_message_content = AesManager.decrypt(data["enc_message_content"], dec_aes_key_client)
        dec_message_content = json.loads(dec_message_content)
        message = dec_message_content['message']
        signature = dec_message_content['signature']

        # check client's signature
        if not RsaManager.verify_signature(json.dumps(message), signature, message['pk']):
            print("Invalid signature!")
            exit()

        resp = self.verify_transaction_existence(message)

        message_to_sign = {
            'response': resp,
            'sid': message['sid'],
            'amount': message['amount'],
            'nc': message['nc']
        }
        signature_to_send = RsaManager.sign(RsaManager.trans_dict_to_hash(message_to_sign), self.private_key)
        message_to_send = {
            'response': resp,
            'sid': message['sid'],
            'signature': signature_to_send
        }
        response_to_client = AesManager.encrypt(json.dumps(message_to_send), dec_aes_key_client)
        connection.sendall(response_to_client.encode())
        connection.close()

    def start_server(self):
        while True:
            client, address = self.ServerSideSocket.accept()
            print('[Bank] Connected to: ' + address[0] + ':' + str(address[1]))
            start_new_thread(self.multi_threaded_client, (client,))
            self.threadCount += 1
            print('[Bank] Thread Number: ' + str(self.threadCount))
        # ServerSideSocket.close()


class Transaction:
    def __init__(self, sid, nc, amount, merchant_identity, card_number, status):
        self.sid = sid
        self.nc = nc
        self.amount = amount
        self.merchant_identity = merchant_identity
        self.card_number = card_number
        self.status = status


class Customer:
    def __init__(self, data):
        self.card_number = data["card_number"]
        self.card_exp_date = data["card_exp_date"]
        self.ccode = data["ccode"]
        self.amount = data["amount"]
        self.phone_number = data["phone_number"]

    def subtract_money(self, data):
        self.amount = str(int(self.amount) - int(data['amount']))

    def verify_balance(self, data):
        return int(data['amount']) < int(self.amount)


class CustomerService:
    def __init__(self):
        c = {
            "card_number": '3141 5926 5358 9793',
            "card_exp_date": '06/23',
            "ccode": '2',
            "amount": '100',
            "phone_number": '+40741130094'
        }
        self.customers = [Customer(c)]
        self.transactions = []

    def add_customer(self, customer):
        self.customers.append(customer)

    def get_customer_by_card_number(self, card_number):
        for c in self.customers:
            if c.card_number == card_number:
                return c
        return None

    def verify_customer(self, data):
        customer = self.get_customer_by_card_number(data["card_number"])

        if data['card_exp_date'] != customer.card_exp_date:
            return False
        if data['ccode'] != customer.ccode:
            return False
        return customer

    def add_transaction(self, data, status):
        self.transactions.append(Transaction(
            data['sid'],
            data['nc'],
            data['amount'],
            data['merchant_identity'],
            data['card_number'],
            status
        ))

    def verify_transaction(self, data):
        for t in self.transactions:
            if t.sid == data['sid'] or t.nc == data['nc']:
                return t
        return False


if __name__ == "__main__":
    BankServer().start_server()
