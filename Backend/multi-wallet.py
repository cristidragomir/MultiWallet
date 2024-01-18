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

# random_string_generation

def generate_random_string(length=20):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string


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

    # password ok at this point
    # json file creation

    mnemonic = Mnemonic.generate()
    secret_key = mnemonic.derive_key(0)
    wallet = UserWallet.from_secret_key(secret_key, provided_password)
    wallet_json_string = wallet.to_json(address_hrp="erd")
    wallet_json = json.loads(wallet_json_string)

    # insert into db minimal information

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO Wallet (w_name, w_address, w_type, owner_id) VALUES (%s, %s, %s, %s)",
                       (w_name, wallet_json['bech32'], "MX", user_id))
    connection.commit()
    
    cursor.close()
    connection.close()

    # retain file on server

    file_name = "MX-" + wallet_json['bech32'] + ".json"
    with open(file_name, 'w') as file:
        file.write(json.dumps(wallet_json))

    return jsonify({"wallet_name": w_name, "json_content": wallet_json}), 200

@app.route("/api/mx-wallet/store", methods=["POST"])
def storeMXWallet():
    sentJsonToServer = request.json

    required_fields = ['keep_wallet_json', 'wallet_name', 'username']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    if sentJsonToServer['keep_wallet_json'] == False:
    
        connection = connectToDb()
        cursor = connection.cursor()

        cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
        user_id = cursor.fetchone()

        cursor.execute("SELECT w_address FROM Wallet WHERE w_type = MX AND owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name'],))
        retrieved_address = cursor.fetchone()

        cursor.close()
        connection.close()

        file_name = "MX-" + retrieved_address + ".json"

        os.remove(file_name)

    return Response(status=200)

@app.route("/api/mx-wallet/details", methods=["GET"])
def getMXWalletDetails():
    sentJsonToServer = request.json

    required_fields = ['username', 'wallet_name']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400
    
    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
    user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'MX' and owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name']))
    erd_address = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    address = Address.new_from_bech32(erd_address)
    account = multiversx_provider.get_account(address)
    balance_to_int = account.balance / (10 ** EGLD_NUM_DECIMALS) 

    return jsonify({"balance": balance_to_int, "nonce": account.nonce}), 200

@app.route("/api/mx-wallet/transactions", methods=["GET"])
def getMXWalletTransactions():
    sentJsonToServer = request.json

    required_fields = ['username', "wallet_name"]
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
    user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'MX' and owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name'],))
    erd_address = cursor.fetchone()[0]

    cursor.close()
    connection.close()
    
    address = Address.new_from_bech32(erd_address)
    transactions = multiversx_provider.get_account_transactions(address)

    list_to_forward = []
    cnt = 0
    for item in transactions:
        cnt += 1
        amnt = item.value / (10 ** EGLD_NUM_DECIMALS)
        list_elem = {
                "hash":item.hash,
                "nonce": item.nonce,
                "sender": item.sender.to_bech32(),
                "receiver": item.receiver.to_bech32(),
                "amount": amnt
            }
        list_to_forward.append(list_elem)

    return jsonify({"number_of_transactions": cnt, "transactions": list_to_forward}), 200
    
@app.route("/api/mx-wallet/send-egld", methods=["POST"])
def sendEGLD():
    sentJsonToServer = request.json

    required_fields = ['sender_username', 'sender_wallet_name', 'amount', 'password', 'receiver', 'uploaded_json', 'description']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    description = sentJsonToServer['description']
    provided_password = sentJsonToServer['password']
    receiver = sentJsonToServer['receiver']
    amount = sentJsonToServer['amount']
    s_w_name = sentJsonToServer['sender_wallet_name']
    s_username = sentJsonToServer['sender_username']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id, hashed_password FROM Users WHERE email = %s", (s_username, ))
    user_id, hashed_password = cursor.fetchone()
    hashed_password = bytes(hashed_password)

    cursor.close()
    connection.close()

    if verify_password(provided_password, hashed_password) == False:
        return jsonify({'error': 'Password provided is incorrect.'}), 400

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (s_username,))
    s_user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'MX' and owner_id = %s AND w_name = %s", (s_user_id, s_w_name,))
    s_erd_address = cursor.fetchone()

    cursor.close()
    connection.close() 

    sender_addr = Address.from_bech32(s_erd_address)
    recv_addr = Address.from_bech32(receiver)

    signer = 0
    if sentJsonToServer['uploaded_json'] == {}:
        # lookup in the server files
        filename = 'MX-' + s_erd_address + '.json'
        signer = UserSigner.from_wallet(Path(f"./{filename}"), provided_password)
    else:
        # process the json given by the user
        key_file_object = sentJsonToServer['uploaded_json']
        kind = key_file_object.get("kind", UserWalletKind.SECRET_KEY.value)

        secret_key = 0
        if kind == "secretKey":
            if address_index is not None:
                raise Exception("address_index must not be provided when kind == 'secretKey'")
            secret_key = UserWallet.decrypt_secret_key(key_file_object, password)
        signer = UserSigner(secret_key)

    transaction = transfer_factory.create_transaction_for_native_token_transfer(
         sender=sender_addr,
         receiver=recv_addr,
         native_amount= TokenPayment.egld_from_amount(amount),
         data=description
    )

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

    # password is ok at this point

    salt = provided_password.encode('utf-8')

    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    acct = Account.from_key(private_key)

    encrypted_private_key = encrypt_message_with_password(private_key, provided_password, salt)

    # create a json file for the wallet

    wallet_json = {
        "address": acct.address,
        "encrypted_private_key": encrypted_private_key.decode('utf-8')
    }

    # insert into the database minimal data

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO Wallet (w_name, w_address, w_type, owner_id) VALUES (%s, %s, %s, %s)",
                       (w_name, wallet_json['address'], "ETH", user_id))
    connection.commit()
    
    cursor.close()
    connection.close()

    # store json persistently on the server

    file_name = "ETH-" + wallet_json['address'] + ".json"
    with open(file_name, 'w') as file:
        file.write(json.dumps(wallet_json))

    return jsonify({"wallet_name": w_name, "json_content": wallet_json}), 200

@app.route("/api/eth-wallet/store", methods=["POST"])
def storeEthereumWallet():
    sentJsonToServer = request.json

    required_fields = ['keep_wallet_json', 'wallet_name', 'username']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    if sentJsonToServer['keep_wallet_json'] == False:
    
        connection = connectToDb()
        cursor = connection.cursor()

        cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
        user_id = cursor.fetchone()

        cursor.execute("SELECT w_address FROM Wallet WHERE w_type = ETH and owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name'],))
        retrieved_address = cursor.fetchone()

        cursor.close()
        connection.close()

        file_name = "ETH-" + retrieved_address + ".json"

        os.remove(file_name)

    return Response(status=200)

@app.route("/api/eth-wallet/details", methods=["GET"])
def getEthWalletDetails():
    sentJsonToServer = request.json

    required_fields = ['username', "wallet_name"]
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
    user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'ETH' and owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name'],))
    eth_address = cursor.fetchone()[0]

    cursor.close()
    connection.close()
    
    if web3.is_connected():
        balance_wei = web3.eth.get_balance(eth_address)
        balance_eth = web3.from_wei(balance_wei, 'ether')
        
        nonce = web3.eth.get_transaction_count(eth_address)
        
        return jsonify({"balance":balance_eth, "nonce":nonce}), 200
    else:
        return jsonify({'error': 'Not connected to Ethereum node'}), 400

    return Response(status=200)

@app.route("/api/eth-wallet/transactions", methods=["GET"])
def getEthWalletTransactions():
    sentJsonToServer = request.json

    required_fields = ['username', "wallet_name"]
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
    user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'ETH' and owner_id = %s AND w_name = %s", (user_id, sentJsonToServer['wallet_name'],))
    eth_address = cursor.fetchone()[0]

    cursor.close()
    connection.close()
    
    url = f"https://api-sepolia.etherscan.io/api?module=account&action=txlist&address={eth_address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey=YourApiKeyToken"

    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code == 200:
        response = response.json()
        transactions_list = response['result']
        list_to_forward = []
        cnt = 0
        for item in transactions_list:
            list_elem = {
                "hash":item['hash'],
                "nonce": item['nonce'],
                "sender": item['from'],
                "receiver": item['to'],
                "amount": web3.from_wei(int(item['value']), 'ether')
            }
            list_to_forward.append(list_elem)
            cnt += 1

        return jsonify({"number_of_transactions": cnt, "transactions": list_to_forward}), 200
    else:
        # Return an error message if the request was not successful
        return jsonify({'error': f'Request to Etherscan API failed with status code {response.status_code}'}), response.status_code

@app.route("/api/eth-wallet/send-eth", methods=["POST"])
def sendETH():
    sentJsonToServer = request.json

    required_fields = ['sender_username', 'sender_wallet_name', 'amount', 'password', 'receiver', 'uploaded_json', 'description']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    description = sentJsonToServer['description']
    provided_password = sentJsonToServer['password']
    receiver = sentJsonToServer['receiver']
    amount = sentJsonToServer['amount']
    s_w_name = sentJsonToServer['sender_wallet_name']
    s_username = sentJsonToServer['sender_username']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id, hashed_password FROM Users WHERE username = %s", (s_username,))
    user_id, hashed_password = cursor.fetchone()
    hashed_password = bytes(hashed_password)

    cursor.close()
    connection.close()

    if verify_password(provided_password, hashed_password) == False:
        return jsonify({'error': 'Password provided is incorrect.'}), 400

    # password is good at this point

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (s_username,))
    s_user_id = cursor.fetchone()

    cursor.execute("SELECT w_address FROM Wallet WHERE w_type = 'ETH' and owner_id = %s AND w_name = %s", (s_user_id, s_w_name,))
    s_eth_address = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    sender_encrypted_private_key = 0
    if sentJsonToServer['uploaded_json'] == {}:
        # lookup in the server files
        filename = 'ETH-' + s_eth_address + '.json'
        with open(filename, 'r') as file:
            data = json.load(file)
        sender_encrypted_private_key = data['encrypted_private_key']
    else:
        # process the json given by the user
        sender_encrypted_private_key = sentJsonToServer['uploaded_json']['encrypted_private_key']

    salt = provided_password.encode('utf-8')
    sender_private_key = decrypt_message_with_password(sender_encrypted_private_key.encode('utf-8'), provided_password, salt) 

    # print(sender_private_key)

    transaction = {
        'to': receiver,
        'value': web3.to_wei(amount, 'ether'),
        'gas': 25000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': web3.eth.get_transaction_count(s_eth_address)
        # data: description.encode('utf-8')
    }
    
    signed_transaction = web3.eth.account.sign_transaction(transaction, sender_private_key)
    transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    
    print(transaction_hash)

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

@app.route("/api/user/login", methods=["POST"])
def loginUser():
    sentJsonToServer = request.json

    required_fields = ['email', 'password']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400
    
    hashed_password = hash_password(sentJsonToServer['password'])
    email = sentJsonToServer['email']

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO Users (username, email, hashed_password) VALUES (%s, %s, %s)", (username, email, hashed_password))
    connection.commit()

    cursor.close()
    connection.close()

    if verify_password(provided_password, hashed_password) == False:
        return jsonify({'error': 'Password provided is incorrect.'}), 400

    # password is correct at this point

    session_token = generate_random_string()

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("UPDATE Users SET session_token = %s WHERE email = %s", (session_token, email))
    connection.commit()

    cursor.close()
    connection.close()
    
    return jsonify({"session_token": session_token}), 200

# General retrieval
@app.route("/api/wallets", methods=["GET"])
def returnWalletsForUser():
    sentJsonToServer = request.json

    required_fields = ['username']
    if not all(field in sentJsonToServer for field in required_fields):
        return jsonify({'error': 'Invalid JSON format. Missing required fields.'}), 400

    connection = connectToDb()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM Users WHERE username = %s", (sentJsonToServer['username'],))
    user_id = cursor.fetchone()

    query = """
        SELECT Wallet.*
        FROM Users
        JOIN Wallet ON Users.id = Wallet.owner_id
        WHERE Users.id = %s;
    """

    # Execute the query
    cursor.execute(query, (user_id,))
    wallets = cursor.fetchall()

    cursor.close()
    connection.close()

    # Print the results
    cnt = 0
    list_to_return = []
    for wallet in wallets:
        cnt += 1
        # print(wallet)
        elem = {
            "name":wallet[1],
            "address":wallet[2],
            "type":wallet[3]
        }
        list_to_return.append(elem)

    return jsonify({"number_of_wallets": cnt, "wallets":list_to_return}), 200

if __name__ == '__main__':
    app.run('0.0.0.0', port=6000, debug=True)
