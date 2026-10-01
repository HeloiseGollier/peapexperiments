#!/usr/bin/env python3
import socket
from ap_harness import Fuzzer

HOST = 'localhost'
PORT = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
conn, address = sock.accept()
print("Connection from: " + str(address))

requests = [Fuzzer.id_request, Fuzzer.challenge, Fuzzer.success_request, Fuzzer.anonymous_identity, Fuzzer.eap_success, Fuzzer.four_way_message_1]

with conn:
    for i in range(10):
        conn.send(Fuzzer.reset.encode())
        print(conn.recv(1024).decode())
        for request in requests:
            print(request)
            conn.send(request.encode())

            response = conn.recv(1024)
            while len(response) == 0:
                response = conn.recv(1024)

            print(response.decode())


conn.close()
