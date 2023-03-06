import socket
import configparser
import threading
from time import sleep
from http.server import BaseHTTPRequestHandler, HTTPServer

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

lock = threading.Lock()

config = configparser.ConfigParser()
config.read('config-server.ini')

g_arrayTransfer = []
g_counterDelete = []
g_socket_count = 0

def socketmanager():

    def sweepkey(result): # because config parser translate bytes to string, and we remove its distinction which is b''
        return result[2:-1]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_threads = []
    ip = config["SOCKET"]["ip"]
    port = int(config["SOCKET"]["port"])
    key = base64.b64decode(sweepkey(config["SOCKET"]["key"]))


    def encrypt_data(message):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC,iv)
        return base64.b64encode(iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size)))

    def decrypt_data(encmessage):
        raw = base64.b64decode(encmessage)
        cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')

    def deleteElementArray(index,threadID):
        # This useful thing permits to sync every threadès. When a thread finished doing a task, 
        # it increment the authorization to delete a part of the array.
        global g_socket_count
        global g_arrayTransfer
        global g_counterDelete

        g_counterDelete[index] += 1
        if g_counterDelete[index] == g_socket_count:
            print(g_arrayTransfer,g_counterDelete)
            g_arrayTransfer.pop(index)
            g_counterDelete.pop(index)
        return False

    hasNotConnection = True
    while hasNotConnection:
        try:
            s.bind((ip, port))
            hasNotConnection = False
        except:
            print("[SOCKET NOTIF ERROR] Port binded, retrying...")
            sleep(2)
            pass
    
    s.listen(5)
    print("[SOCKET NOTIF] Server is listening...")
    end = False

    def handle_client(conn,addr):
        print(f"[SOCKET NOTIF] : New connection from {addr} established.")
        connected = True
        global g_socket_count
        global g_arrayTransfer
        global g_counterDelete
        try:
            groups = decrypt_data(conn.recv(512)).split("|")
            while connected:
                if(end): # when server closes we need to kill all the threadings
                    break
                if (len(g_arrayTransfer) == 0):
                    sleep(1)
                    conn.send(encrypt_data("ping"))
                    continue
                lock.acquire() # chacun son tour...
                for element in g_arrayTransfer:
                    deleteElementArray(g_arrayTransfer.index(element),threading.get_ident())
                    for group in groups:
                        if not element[0] == group:
                            continue
                        data = ""
                        for e in element:
                            data += e + "|" # destinateur et le message séparé
                        conn.send(encrypt_data(data[:-1]))
                        break
                lock.release()
                sleep(0.5) # let the time for  the other thread to accomplish
            g_socket_count -= 1
            conn.close()

        except socket.error as e:
            import errno
            if e.errno == errno.ECONNRESET:
                print(f"[SOCKET NOTIF ERROR] : User '{addr}' disconnect by user.")

        except Exception as e:
            print(f"[SOCKET NOTIF ERROR] : Exception : {e.__class__.__name__ } - {e}.")
        finally:
            print("[SOCKET NOTIF ERROR] : Peer closed.")
            g_socket_count -= 1
            print(f"[SOCKET NOTIF] : Remaining sockets : {g_socket_count}")
            conn.close()

    try:
        while True:
            clientsocket, address = s.accept()
            global g_socket_count
            g_socket_count += 1
            t = threading.Thread(target=handle_client,args=(clientsocket,address))
            t.start()

            socket_threads.append(t)
            print(f"[SOCKET NOTIF] : Number of sockets : {g_socket_count}")

    except KeyboardInterrupt:
        print("Closing server...")
    finally:
        if s:
            s.close()
        for t in socket_threads:
            t.join()
        end = True

def httpserver():
    class HTTPHandler(BaseHTTPRequestHandler):
        server_version = ""
        sys_version = ""

        def handle(self): # supress 'connection reset by peer' error
            try:
                BaseHTTPRequestHandler.handle(self)
            except socket.error:
                print(f"[HTTP SERVER ERROR] Peer {self.client_address[0]} (maybe scanning ports ?) reset the connection. ")

        def _set_response(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_GET(self):
            self.send_response(301)
            self.send_header('Location', "https://www.tomhk.fr") # redirect immediately
            print(f"[HTTP SERVER ERROR] Ip {self.client_address[0]} is trying to GET HTML from server...")
            self.end_headers()

        def do_POST(self):
            if self.client_address[0] not in config["HTTPSERVER"]["authorized"].split("|"):
                return

            content_length = int(self.headers['Content-Length']) # <--- Gets the size of data

            post_data = self.rfile.read(content_length).decode('utf-8') # <--- Gets the data itself
            self._set_response()
            self.wfile.write("POST request is {}".format(post_data).encode('utf-8'))

            data = post_data.split("|")
            if data[0] != "SOCKETMANAGER":
                return

            if g_socket_count == 0:
                print("[HTTP SERVER] No notification will be sent, because no sockets are available.")
                return

            global g_arrayTransfer
            global g_counterDelete

            g_arrayTransfer.append(data[1:])
            g_counterDelete.append(0)
            

    
    ip = config["HTTPSERVER"]["ip"]
    port = int(config["HTTPSERVER"]["port"])

    server_address = (ip, port)
    httpd = HTTPServer(server_address, HTTPHandler)
    try:
        httpd.serve_forever()
    except ConnectionResetError as e:
        print('[HTTP SERVER] Connection error.')
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

thread_socketmanager = threading.Thread(target=socketmanager)
thread_httpserver = threading.Thread(target=httpserver)

thread_socketmanager.start()
thread_httpserver.start() # post only !