import random
import configparser

from twilio.rest import Client


def send_otp(to_number):
    config = configparser.ConfigParser()
    config.read("config.ini")

    account_sid = config.get("Twilio", "account_sid")
    auth_token = config.get("Twilio", "auth_token")
    from_number = config.get("Twilio", "from_number")
    client = Client(account_sid, auth_token)
    message = str(random.randint(10000, 99999))
    client.messages.create(
        to=to_number,
        from_=from_number,
        body=message
    )
    return message
