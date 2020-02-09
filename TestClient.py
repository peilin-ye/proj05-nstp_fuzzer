import struct, time, threading, hashlib, sys, socket
import nstp_v3_pb2, nacl.utils
import nacl.bindings.crypto_kx as crypto_kx
from nacl.bindings.crypto_secretbox import crypto_secretbox_open, crypto_secretbox, crypto_secretbox_NONCEBYTES 
from nacl.bindings.randombytes import randombytes
import nacl.pwhash as pwhash


def send(sock, obj, encrypt=True):
    print("Sent: {0}".format(obj))
    bytes_to_send= obj.SerializeToString()

    if encrypt:
        global client_tx
        nonce= randombytes(crypto_secretbox_NONCEBYTES)
        encrypted_bytes= crypto_secretbox(bytes_to_send, nonce, client_tx)
        nstp_message= nstp_v3_pb2.NSTPMessage()
        nstp_message.encrypted_message.ciphertext= encrypted_bytes
        nstp_message.encrypted_message.nonce= nonce
        bytes_to_send= nstp_message.SerializeToString()

    sock.sendall(len(bytes_to_send).to_bytes(2, byteorder="big") + bytes_to_send)

def process_response(sock): # message= message received

    header = sock.recv(2)
    message_length, = struct.unpack('>H', header) 
    message= sock.recv(message_length)

    nstp_message= nstp_v3_pb2.NSTPMessage()
    nstp_message.ParseFromString(message)

    message_type = nstp_message.WhichOneof('message_')
    if message_type == 'server_hello':
        process_server_hello(nstp_message)
        print(nstp_message)
    elif message_type == 'encrypted_message':
        process_encrypted_message(nstp_message)
    elif message_type == 'error_message':
        print(nstp_message)
    else:
        print("Got unkwown NSTP message")

def process_server_hello(nstp_message): # we only want the server_hello to grab the session keys
    server_hello= nstp_message.server_hello
    
    global client_public, client_private
    global client_rx, client_tx
    client_rx, client_tx = crypto_kx.crypto_kx_client_session_keys(client_public, client_private, server_hello.public_key)

def process_encrypted_message(nstp_message):
    global client_rx

    encrypted_message=nstp_message.encrypted_message

    try:
        decrypted_bytes= crypto_secretbox_open(encrypted_message.ciphertext, encrypted_message.nonce, client_rx)
    except Exception as e:
        print("Error decrypting message")
        return

    decrypted_message=nstp_v3_pb2.DecryptedMessage()
    decrypted_message.ParseFromString(decrypted_bytes)

    decrypted_message_type = decrypted_message.WhichOneof('message_')

    print(decrypted_message)


if __name__ == '__main__':
    server_address = ('localhost', 22300)
    
    global client_public, client_private
    client_public, client_private= crypto_kx.crypto_kx_keypair()
    
    messages = list()
    ############################################################
    # Test case0: check out-of-spec protocol
    m0= nstp_v3_pb2.NSTPMessage()
    m0.client_hello.major_version=1000
    m0.client_hello.minor_version=1
    m0.client_hello.user_agent='The user'
    m0.client_hello.public_key= client_public
    m0= (m0, False) 

    def case0():
        print("Testing case 0...")
        ms = list()
        ms.append(m0) # client_hello (bad nstp version)
        return ms
    
    # uncomment this line to use this message
    # messages = case0()
    ############################################################
    # Test case1: check login attemp threshould
    m1= nstp_v3_pb2.NSTPMessage()
    m1.client_hello.major_version=3
    m1.client_hello.minor_version=1
    m1.client_hello.user_agent='The user'
    m1.client_hello.public_key= client_public
    m1= (m1, False) 

    m2= nstp_v3_pb2.DecryptedMessage()
    m2.auth_request.username='user'
    m2.auth_request.password='wrong password'
    m2= (m2, True)

    # If threshold was 3, this shouldn't work despite sending correct pwd
    m3= nstp_v3_pb2.DecryptedMessage()
    m3.auth_request.username='user'
    m3.auth_request.password='password' 
    m3= (m3, True)
    
    def case1():
        print("Testing case 1...")
        ms = list()
        ms.append(m1) # client_hello
        ms.append(m2) # auth_request (bad)
        ms.append(m2) # auth_request (bad)
        ms.append(m2) # auth_request (bad)
        ms.append(m3) # auth_request (good)
        return ms
    # uncomment next line to use
    # messages = case1()
    ############################################################
    # Test case2: load non-existing private key
    m4 = nstp_v3_pb2.DecryptedMessage()
    m4.load_request.key = "qazxswedcvfrtgbnhyujmkiolp0987654321"
    m4.load_request.public = False
    m4 = (m4, True)

    def case2():
        print("Testing case 2...")
        ms = list()
        ms.append(m1) # client_hello
        ms.append(m3) # auth_request
        ms.append(m4) # (public) load_request "qazxswedcvfrtgbnhyujmkiolp0987654321"
        return ms
    # uncomment next line to use
    # messages = case2()
    ############################################################
    # Test case3: load non-existing public key
    m5 = nstp_v3_pb2.DecryptedMessage()
    m5.load_request.key = "qazxswedcvfrtgbnhyujmkiolp0987654321"
    m5.load_request.public = True
    m5 = (m5, True)
    
    def case3():
        print("Testing case 3...")
        ms = list()
        ms.append(m1) # client_hello
        ms.append(m3) # auth_request
        ms.append(m5) # (private) load_request "qazxswedcvfrtgbnhyujmkiolp0987654321"    
        return ms
    # uncomment next line to use
    # messages = case3()
    ############################################################
    # Test case4: out-of-phase (Initialization)
    def case4():
        print("Testing case 4...")
        ms = list()
        ms.append(m3) # auth_requset (out-of-phase)
        return ms
    # uncomment next line to use
    # messages = case4()   
    ############################################################
    # Test case5: out-of-phase (Authentication)
    def case5():
        print("Testing case 5...")
        ms = list()
        ms.append(m1) # client_hello
        ms.append(m5) # (private) load_request "qazxswedcvfrtgbnhyujmkiolp0987654321" (out-of-phase)
        return ms
    # uncomment next line to use
    # messages = case5()   
    ############################################################
    # Test case6: out-of-phase (Established)
    def case6():
        print("Testing case 6...")
        ms = list()
        ms.append(m1) # client_hello
        ms.append(m3) # auth_requset
        ms.append(m1) # client_hello (out-of-phase)
        return ms    
    # uncomment next line to use
    # messages = case6()          
    ############################################################
    
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)

        for m in messages:    
            send(sock, m[0], m[1])           
            process_response(sock)
