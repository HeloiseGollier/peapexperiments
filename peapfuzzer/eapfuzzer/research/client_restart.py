#!/usr/bin/env python3
import signal
import os
import subprocess
import socket
import time
import sys
from config import CONFIG

# wpa_supplicant = 'sudo wpa_supplicant -D nl80211 -i wlan2 -c client.conf'
wpa_supplicant = 'sudo wpa_supplicant -D nl80211 -i wlan2 -c conffiles/peapv0.conf'
anonymous_wpa_supplicant = "sudo ./../../../wpa_supplicant-2.10/wpa_supplicant/wpa_supplicant -D nl80211 -i wlan2 -c conffiles/peapv0.conf -dd -K"

iwd = 'sudo iwd -i wlan2'
ubuntu_off = 'nmcli connection down \"eapfuzzer\"'
ubuntu_on = 'nmcli connection up \"eapfuzzer\"'

client = CONFIG["local_sut"]
HOST = 'localhost'
PORT = 9090
ready = "ready\n"

if client == "wpa_supplicant":
    cmd = wpa_supplicant
elif client == "iwd":
    cmd = iwd
elif client == "ubuntu":
    cmd = ubuntu_on
elif client == "anonymous_wpa_supplicant":
    cmd = anonymous_wpa_supplicant
elif client is None:
    print("No client specified")
    exit()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
conn, address = sock.accept()
print("Connection from: " + str(address))

with conn:
    pro = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)


    def handler(signum, frame):
        os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
        conn.close()
        exit(1)


    signal.signal(signal.SIGINT, handler)

    while True:
        data = conn.recv(1024)
        if len(data.decode()) != 0:
            if data.decode() == "rst\n":
                print('rst')
                if client == "ubuntu":
                    pro = subprocess.Popen(ubuntu_off, shell=True, preexec_fn=os.setsid)
                else:
                    os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
                time.sleep(2)  # O.5 for wpa_supplicant and 2 for iwd
                print("-----------------RESTARTING--------------")
                pro = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
                conn.send(ready.encode())
            elif data.decode() == "closing":
                os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
                conn.close()
                exit()
