# E-Commerce App

Implementation of the e-commerce protocol for carrying out transactions involving the purchase of products. Uses multi-threaded servers for the merchant and the bank. Implements 2FA for client validation. All the communications between instances are being made using hybrid encryption (RSA manager & AES manager). The authenticity of messages is verified with signature checking.

## Features

- **Multi-Threaded Servers**: The project employs multi-threaded servers for both the merchant and the bank, allowing for efficient and concurrent processing of transactions.

- **Two-Factor Authentication (2FA)**: To enhance client validation, the protocol integrates a Two-Factor Authentication mechanism. Users receive a One-Time Password (OTP) via SMS from the bank, ensuring an additional layer of security.

- **Hybrid Encryption**: All communications between instances within the system are secured using hybrid encryption. The RSA manager encrypts keys, while the AES manager handles symmetric encryption. This combination provides robust protection for sensitive data.

- **Message Authenticity Verification**: To guarantee the authenticity of messages exchanged within the system, digital signatures are used. Almost each message is accompanied by a signature, allowing recipients to verify the integrity and source of the message.

## Application Flow

### User Interaction

1. Users interact with the system through a graphical user interface, adding products to their cart and placing orders.

2. Clients enter their credit card information and receive an OTP via SMS from the bank (Twilio is used for SMS functionality).

3. Users provide the OTP to the application to complete the transaction.

### E-Commerce Protocol

1. A session-specific RSA public/private key pair is generated for the client.

2. The client initiates communication with the merchant by sending a message containing:
   - The client's RSA public key, encrypted with a symmetric key.
   - The symmetric key, encrypted with the merchant's public key.

3. The merchant responds with a message containing:
   - A unique transaction identifier.
   - A signature over the identifier.
   The response is also encrypted using hybrid encryption.

4. The client sends payment information to the merchant, who forwards it to the bank along with its signature over the info for authenticity verification.

5. The bank validates the received data, including the OTP provided by the client during 2FA.

6. If both data validation and account balance checks pass successfully, the bank sends a confirmation message to the merchant for processing. Otherwise, an abort message is transmitted.

7. In cases where the client sends payment but does not receive a response from the merchant, a timeout interval is defined to identify potential issues. If the timeout expires, the client sends a message to the bank, which checks for a corresponding message and responds accordingly.
