import socket
import configparser
from time import sleep
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def sweepkey(result): # because configparser translate bytes to string, and we remove its distinction which is b''
    return result[2:-1]

def encrypt_data(message):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC,iv)
    return base64.b64encode(iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size)))

def decrypt_data(encmessage):
    raw = base64.b64decode(encmessage)
    cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')
        
config = configparser.ConfigParser()
config.read('config-client.ini')

ip = config["SOCKET-OVH1"]["ip"]
port = int(config["SOCKET-OVH1"]["port"])
groups = config["SOCKET-OVH1"]["groups"]
key = base64.b64decode(sweepkey(config["SOCKET-OVH1"]["key"]))

print("SOCKET CLIENT : Listening...")
connected = False
while True:
    if not connected:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            
            connected = True
            print("SOCKET CLIENT : Connected !")
            s.send(encrypt_data(groups))
        except ConnectionRefusedError as e: 
            print("Could not connect to server... Retry in 5 seconds.")
            sleep(5)
            continue
    try:
        
        data = decrypt_data(s.recv(1024))
        if len(data) == 0:
            print("Server closed.")
            connected = False
        elif data == "ping":
            continue
        dataArray = data.split('|')
        print(f"{dataArray[1]} : {dataArray[2]}")

    except ValueError as e:
        print("Server disconnect...")
        connected = False
        sleep(5)
    except Exception as e:
        print(f"Client closed because of error : {e.__class__.__name__ } - {e}")
        connected = False
        sleep(5)


        



