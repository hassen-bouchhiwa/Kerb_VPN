import threading
import pytun
import select
import socket
import kerberos
import binascii
import os
import struct
import time
import json
import base64
from mycipher import encrypt_aes256, decrypt_aes256, myhash

def secureEncode(machine_id,packet,TGS,enc_key):
    packet_64 = base64.b64encode(packet).decode('utf-8')
    json = f'"machine_id": "{machine_id}","packet_64": "{packet_64}","TGS": "{TGS}" '
    json = "{"+json+"}" 
    json_enc = encrypt_aes256(enc_key, json)
    json_enc_64 =  base64.b64encode(json_enc).decode('utf-8')
    hmac = myhash(json+enc_key)
    data = json_enc_64 + "." + hmac
    return data
def secureDecode(data):
    packet_64_enc_64, hmac = data.split(".")
    packet_64_enc = base64.b64decode(packet_64_enc_64)
    packet_64= decrypt_aes256(enc_key,packet_64_enc)
    if hmac == myhash(packet_64+enc_key):
        packet = base64.b64decode(packet_64)
        return packet
    else:
        return "No intergrety verified for this packet"

def parse_json_file():
    with open('ppp.json', 'r') as f:
        data = json.load(f)
    myIP = data['myIP']
    serverIP = data['serverIP']
    sendPort = data['sendPort']
    enc_key = data['enc_key']
    kerb_key = data['kerb_key']
    machine_id = data['machine_id']

def create_tun():
    tun = pytun.TunTapDevice(name='tun0', flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
    tun.addr = myIP
    tun.netmask = '255.255.255.0'
    tun.mtu = 1500
    tun.up()

def getTGS():
    service_name = 'vpn@kdc.insat.tn'
    #specify that mutual authentication and sequence-based authentication should be used in the GSSAPI authentication process.
    flags = kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_SEQUENCE_FLAG
    kdc_hostname = 'kdc.insat.tn'
    realm = 'INSAT.TN'
    keytab_path = '/etc/krb5.keytab'
    ccache_path = '/tmp/krb5cc_0'
    # Authenticate the user's credentials

    principal = f"{machine_id}/{kdc_hostname}@{realm}"
    os.system(f'echo "{kerb_key}" > pass.txt')
    print(f"kinit -c {ccache_path} {machine_id}/{kdc_hostname}@{realm} < pass.txt")
    #os.system(f"kinit -c {ccache_path} {machine_id}/{kdc_hostname}@{realm} < pass.txt" )
            
    try:
        result, client_context = kerberos.authGSSClientInit(service_name)
    except kerberos.GSSError as e:
        print(f"Error initializing client context: {e}")
        exit()
    print(client_context)
    print(result)  

    try:
        preauth_token = kerberos.authGSSClientStep(client_context, "")
    except kerberos.GSSError as e:
        print(e)
    print(preauth_token)
    TGS = kerberos.authGSSClientResponse(client_context)
    print("Response: ",TGS)
    return TGS
def socketInit(TGS):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (serverIP, sendPort)
    client_socket.connect(server_address)
    TGS_enc = encrypt_aes256(enc_key,TGS)
    TGS_enc_64 = base64.b64encode(TGS_enc).decode('utf-8')
    first_msg = f'"machine_id":"{machine_id}","TGS_enc_64":"{TGS_enc_64}"'
    first_msg = "{"+first_msg+"}" 
    print(first_msg)
    client_socket.send(first_msg.encode())
    return client_socket

def sniffer():
    global client_socket
    while True:
        r, w, x = select.select([tun], [], [])
        if tun in r:
            packet = tun.read(tun.mtu)
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])
            print("Packet goes from ",src_ip,' to ',dst_ip)
            if (src_ip==myIP):
                data = secureEncode(machine_id,packet,TGS,enc_key)
                client_socket.sendall(data.encode())
def listener():
    global client_socket
    while True:
        try:
            # receive data from the client
            json_data = client_socket.recv(1024)
            print("weslet haja")
            if not data:
                break
            json_string = json_data.decode()
            packet = secureDecode(json_string)
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])
            print("Packet goes from ",src_ip,' to ',dst_ip)
            if(dst_ip==myIP):
                print('Regenerating packet ...')
                tun.write(packet)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    parse_json_file()
    create_tun()
    TGS = getTGS()
    client_socket = socketInit(TGS)

    thread_1 = threading.Thread(target=listener)
    thread_2 = threading.Thread(target=sniffer)


    thread_1.start()
    thread_2.start()
