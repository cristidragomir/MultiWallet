
from flask import Flask, request, Response
from flask.json import jsonify
import json
import psycopg2

from multiversx_sdk_wallet import Mnemonic
from multiversx_sdk_wallet import UserWallet
from pathlib import Path

app = Flask(__name__)

def connectToDb():
    return psycopg2.connect(host="localhost", 
        port = 5432, database="multi-wallet-db", 
        user="postgres", 
        password="docker")

def checkIfStringIsFloat(x):
    try:
        conversion = float(x)
    except (TypeError, ValueError):
        return False
    else:
        return True

def checkIfStringIsInteger(x):
    try:
        conversion = int(x)
    except (TypeError, ValueError):
        return False
    else:
        return True

def checkIfStringIsDate(dateStr):
    if len(dateStr) != len("AAAA-LL-ZZ"):
        return False
    substr = dateStr[0:4]
    if substr.isdigit() == False:
        return False
    if dateStr[4] != '-':
        return False
    substr = dateStr[5:7]
    if substr.isdigit() == False:
        return False
    if dateStr[7] != '-':
        return False
    substr = dateStr[8:10]
    if substr.isdigit() == False:
        return False
    return True

@app.route("/api/test", methods=["POST"])
def postCountry():
    conn = connectToDb()
    cur = conn.cursor()
    
    sentJsonToServer = request.json
    codeToRet = 200

    cur.execute("""INSERT INTO test(msg_input) values (%s)""", (sentJsonToServer['field'],))
    conn.commit()

    cur.close()
    conn.close()
    return sentJsonToServer, codeToRet

@app.route("/api/create-mx-wallet", methods=["POST"])
def createMultiversXWallet():
    codeToRet = 200

    mnemonic = Mnemonic.generate()
    words = mnemonic.get_words()

    print(words)

    file_path = Path("./output/walletWithMnemonic.json")

    # Create directories if they don't exist
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # wallet = UserWallet.from_mnemonic(mnemonic.get_text(), "password")
    # wallet.save(file_path)

    secret_key = mnemonic.derive_key(0)
    public_key = secret_key.generate_public_key()

    print("Secret key:", secret_key.hex())
    print("Public key:", public_key.hex())

    wallet = UserWallet.from_secret_key(secret_key, "password")
    wallet.save(Path("./output/wallet.json"), address_hrp="erd")

    return jsonify(result.stdout), codeToRet


if __name__ == '__main__':
    app.run('0.0.0.0', port=6000, debug=True)
