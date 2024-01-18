import psycopg2
import requests
import bcrypt
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet

# Flask imports

from flask import Flask, request, send_file, Response
from flask.json import jsonify
from flask_cors import CORS

# MultiversX imports

from multiversx_sdk_core import Address
from multiversx_sdk_network_providers import ApiNetworkProvider
from multiversx_sdk_wallet import Mnemonic
from multiversx_sdk_wallet import UserWallet
from multiversx_sdk_wallet import UserSigner
from multiversx_sdk_core import TokenComputer, TokenPayment, TransactionComputer
from multiversx_sdk_core.transaction_factories import TransferTransactionsFactory
from multiversx_sdk_core.transaction_factories import TransactionsFactoryConfig
from multiversx_sdk_core.constants import (EGLD_NUM_DECIMALS,
                                           EGLD_TOKEN_IDENTIFIER)

# Ethereum imports

from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
import secrets

# Cryptography imports

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# MultiversX global variables

multiversx_provider = ApiNetworkProvider("https://testnet-api.multiversx.com")
config = TransactionsFactoryConfig("T")
transfer_factory = TransferTransactionsFactory(config, TokenComputer())

#Ethereum global variables

web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/Y_rCK6Iw8j2YsLwr7RD4VGjlfGWNeiYt'))

app = Flask(__name__)
CORS(app) 

def connectToDb():
    return psycopg2.connect(host="localhost", 
        port = 5432, database="multi-wallet-db", 
        user="postgres", 
        password="docker")

# password hashing

def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(input_password, stored_hashed_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password)

# encrypt/decrypt methods

def generate_key_from_password(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key length
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_message_with_password(message, password, salt):
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(base64.urlsafe_b64encode(key))
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_message_with_password(encrypted_message, password, salt):
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(base64.urlsafe_b64encode(key))
    decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
    return decrypted_message


# MultiverseX endpoints

@app.route("/api/mx-wallet/create", methods=["POST"])
def createMultiversXWallet():
    sentJsonToServer = request.json

    required_fields = ['password', 'user_mail', 'wallet_name']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    provided_password = sentJsonToServer['password']
    received_email = sentJsonToServer['user_mail']
    w_name = sentJsonToServer['wallet_name']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id, hashed_password FROM Users WHERE email = %s", (received_email,))
    user_id, hashed_password = cursor.fetchone()
    hashed_password = bytes(hashed_password)

    cursor.close()
    connection.close()

    if verify_password(provided_password, hashed_password) == False:
        return jsonify({'error': 'Password provided is incorrect.'}), 400

    mnemonic = Mnemonic.generate()
    secret_key = mnemonic.derive_key(0)
    wallet = UserWallet.from_secret_key(secret_key, provided_password)
    wallet_json_string = wallet.to_json(address_hrp="erd")
    wallet_json = json.loads(wallet_json_string)

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO Wallet (w_name, w_address, w_type, owner_id) VALUES (%s, %s, %s, %s)",
                       (w_name, wallet['bech32'], "MX", user_id))

    # Commit the transaction
    connection.commit()
    
    cursor.close()
    connection.close()

    return jsonify({"wallet_name": w_name, "json_content": wallet_json}), 200

@app.route("/api/mx-wallet/store", methods=["POST"])
def storeMXWallet():
    # fields: [keep_wallet_json - boolean]
    sentJsonToServer = request.json

    # required_fields = ['address', 'bech32', 'crypto', 'id', 'kind', 'version']
    # if not all(field in sentJsonToServer for field in required_fields):
    #     return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    # file_name = "MX-" + sentJsonToServer['bech32'] + ".json"
    # with open(file_name, 'w') as file:
    #     file.write(json.dumps(sentJsonToServer))

    return Response(status=200)

@app.route("/api/mx-wallet/details", methods=["GET"])
def getMXWalletDetails():
    sentJsonToServer = request.json

    required_fields = ['address']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400
    
    erd_address = sentJsonToServer['address']
    address = Address.new_from_bech32(sentJsonToServer['address'])
    account = multiversx_provider.get_account(address)

    print(f"Wallet address: {erd_address}")
    print("Nonce:", account.nonce)
    balance_to_int = account.balance / (10 ** EGLD_NUM_DECIMALS) 
    print("Balance:", balance_to_int)

    return Response(status=200)

@app.route("/api/mx-wallet/transactions", methods=["GET"])
def getMXWalletTransactions():
    sentJsonToServer = request.json

    required_fields = ['address']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400
    
    erd_address = sentJsonToServer['address']

    address = Address.new_from_bech32(erd_address)
    transactions = multiversx_provider.get_account_transactions(address)

    for item in transactions:
        print("Hash: ", item.hash)
        print("Type: ", item.type)
        print("Nonce:", item.nonce)
        print("Sender:", item.sender.to_bech32())
        print("Receiver: ", item.receiver.to_bech32())

    return Response(status=200)    

@app.route("/api/mx-wallet/send-egld", methods=["POST"])
def sendEGLD():
    sentJsonToServer = request.json

    # Fields: [username, wallet-name, amount, password, receiver, uploaded_json:{}, description]

    required_fields = ['receiver', 'amount', 'password']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    description = 'N/A'
    if sentJsonToServer['description']:
        description = sentJsonToServer['description']

    sender_addr = Address.from_bech32('erd1auh98yx3c03xqgjctskz080pr7lqd5zt9akgh4pqsp8sun2qpg7qlez8cg')
    recv_addr = Address.from_bech32(sentJsonToServer['receiver'])

    transaction = transfer_factory.create_transaction_for_native_token_transfer(
        sender=sender_addr,
        receiver=recv_addr,
        native_amount= TokenPayment.egld_from_amount(sentJsonToServer['amount']),
        data=description
    )

    signer = UserSigner.from_wallet(Path("./erd1auh98yx3c03xqgjctskz080pr7lqd5zt9akgh4pqsp8sun2qpg7qlez8cg.json"), sentJsonToServer['password'])
    transaction.signature = signer.sign(TransactionComputer().compute_bytes_for_signing(transaction))

    multiversx_provider.send_transaction(transaction)

    return Response(status=200)

# Ethereum endpoints

@app.route("/api/eth-wallet/create", methods=["POST"])
def createEthereumWallet():
    sentJsonToServer = request.json

    required_fields = ['password', 'user_mail', "wallet_name"]
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    provided_password = sentJsonToServer['password']

    # check if password is valid by checking bcrypt hash already stored in db when user created account
    # if not don't proceed
    provided_password = sentJsonToServer['password']
    received_email = sentJsonToServer['user_mail']
    w_name = sentJsonToServer['wallet_name']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id, hashed_password FROM Users WHERE email = %s", (received_email,))
    user_id, hashed_password = cursor.fetchone()
    hashed_password = bytes(hashed_password)

    cursor.close()
    connection.close()

    if verify_password(provided_password, hashed_password) == False:
        return jsonify({'error': 'Password provided is incorrect.'}), 400

    # password ok
    salt = provided_password.encode('utf-8')

    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    acct = Account.from_key(private_key)

    encrypted_private_key = encrypt_message_with_password(private_key, provided_password, salt)

    # create a json file for the wallet
    # add it in the database

    wallet_json = "wallet_json"

    return jsonify({"wallet_name": w_name, "json_content": wallet_json}), 200

@app.route("/api/eth-wallet/store", methods=["POST"])
def storeEthereumWallet():
    sentJsonToServer = request.json

    required_fields = ['eth_address', 'encrypted_private_key']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    file_name = "ETH-" + sentJsonToServer['eth_account'] + ".json"
    with open(file_name, 'w') as file:
        file.write(json.dumps(sentJsonToServer))

    # create a binding between db record and filename
    # a table named WALLET with fields: id, bech32_address, hex_address, name, user_id

    return Response(status=200)

@app.route("/api/eth-wallet/details", methods=["GET"])
def getEthWalletDetails():
    sentJsonToServer = request.json

    required_fields = ['address']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    eth_address = sentJsonToServer['eth_address']

    if web3.is_connected():
        balance_wei = web3.eth.get_balance(eth_address)
        balance_eth = web3.from_wei(balance_wei, 'ether')
        
        nonce = web3.eth.get_transaction_count(eth_address)
        
        print(f"Account: {eth_address}")
        print(f"Balance: {balance_eth} ETH")
        print(f"Nonce: {nonce}")
    else:
        print("Not connected to Ethereum node")

    return Response(status=200)

@app.route("/api/eth-wallet/transactions", methods=["GET"])
def getEthWalletTransactions():
    sentJsonToServer = request.json

    required_fields = ['eth_address']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    eth_address = sentJsonToServer['eth_address']
    
    url = f"https://api-sepolia.etherscan.io/api?module=account&action=txlist&address={eth_address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey=YourApiKeyToken"

    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code == 200:
        # Return the JSON response from the Etherscan API
        return jsonify(response.json()), 200
    else:
        # Return an error message if the request was not successful
        return jsonify({'error': f'Request to Etherscan API failed with status code {response.status_code}'}), response.status_code

@app.route("/api/eth-wallet/send-eth", methods=["POST"])
def sendETH():
    sentJsonToServer = request.json

    required_fields = ['sender', 'encrypted_private_key', 'receiver', 'amount', 'password']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    sender_addr = sentJsonToServer['sender']
    
    # encrypted_private_key should be decrypted using password provided
    
    sender_private_key = sentJsonToServer['encrypted_private_key']
    recv_address = sentJsonToServer['receiver']
    amount_to_send = sentJsonToServer['amount']

    transaction = {
        'to': recv_address,
        'value': web3.to_wei(amount_to_send, 'ether'),
        'gas': 21000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': web3.eth.get_transaction_count(sender_addr),
    }

    signed_transaction = web3.eth.account.sign_transaction(transaction, sender_private_key)
    transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    
    print("Transaction Hash:", transaction_hash)

    return Response(status=200)

# User endpoints

@app.route("/api/user/create", methods=["POST"])
def createUser():
    sentJsonToServer = request.json

    required_fields = ['username', 'email', 'password']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    hashed_password = hash_password(sentJsonToServer['password'])
    username = sentJsonToServer['username']
    email = sentJsonToServer['email']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO Users (username, email, hashed_password) VALUES (%s, %s, %s)", (username, email, hashed_password))
    connection.commit()

    cursor.close()
    connection.close()

    # return rand_string to be a session token, to put into db
    return Response(status=200)

@app.route("api/user/login", methods=["POST"])
def loginUser():
    # fields: [email, password]
    # return rand_string to be a session token, to put into db
    return Response(status=200)

if __name__ == '__main__':
    app.run('0.0.0.0', port=6000, debug=True)
