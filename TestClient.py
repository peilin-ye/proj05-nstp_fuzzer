import struct, time, threading, hashlib, sys
import nstp_v3_pb2, nacl.utils
import nacl.bindings.crypto_kx as crypto_kx
import nacl.bindings.crypto_secretbox as secret_box
import nacl.bindings.randombytes as randombytes
import nacl.pwhash as pwhash

check_response


def send(sock, obj, encrypt=True):
    print("{0}: Sent: {1}".format(self.client_address, obj))
    bytes_to_send= obj.SerializeToString()

    if encrypt:
        nonce= randombytes.randombytes(secret_box.crypto_secretbox_NONCEBYTES)
        encrypted_bytes= secret_box.crypto_secretbox(bytes_to_send, nonce, self.server_tx)
        encrypted_message= nstp_v3_pb2.EncryptedMessage()
        encrypted_message.ciphertext= encrypted_bytes
        encrypted_message.nonce= nonce
        bytes_to_send= encrypted_message.SerializeToString()

    sock.sendall(len(bytes_to_send).to_bytes(2, byteorder="big") + bytes_to_send)

    global client_rx, client_tx
    client_rx, client_tx = crypto_kx.crypto_kx_client_session_keys

def process_response(message): # message= message received
    nstp_message= nstp_v3_pb2.NSTPMessage()
    nstp_message.ParseFromString(message)

    print("Received: {0}".format( nstp_message))

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
    global client_public, client_private
    global client_rx, client_tx

    server_hello= nstp_message.server_hello

    client_rx, client_tx = crypto_kx.crypto_kx_client_session_keys(client_public, client_private, server_hello.public_key)

def process_encrypted_message(nstp_message):

    encrypted_message=nstp_message.encrypted_message

    try:
        decrypted_bytes= secret_box.crypto_secretbox_open(encrypted_message.ciphertext, encrypted_message.nonce, self.server_rx)
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
    
    crypto_kx_server_session_keys(server_public, server_private, self.public_key)

    messages=list()

    # Test case1: check login attemp threshould

    # Test case2: access non-existing private key

    # Test case3: access non-existing public key
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)

        for m in messages:    
            send(sock, m])
            response = sock.recv(6500)
            print("Received: {}".format(response))
            check_response(response, m)
