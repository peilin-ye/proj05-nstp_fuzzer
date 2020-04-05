import argparse, socket, struct, logging, time, datetime
import utils.ProtoCrafter
import nacl.utils
import utils.nstp_v3_pb2 as nstp_v3_pb2
from utils.ProtoCrafter import craft_client_hello, craft_auth_request, craft_ping_request, craft_load_request, craft_store_request # TODO Add missing imports here 
import nacl.bindings.crypto_kx as crypto_kx
from nacl.bindings.crypto_secretbox import crypto_secretbox_open, crypto_secretbox, crypto_secretbox_NONCEBYTES 
from nacl.bindings.randombytes import randombytes

CLIENT_HELLO      = 1   # client_hello = 1;
SERVER_HELLO      = 2   # server_hello = 2;
ERROR_MESSAGE     = 3   # error_message = 3;
DECRYPTED_MESSAGE = 4   # decrypted_message = 4;

def pack(x):
    return (len(x).to_bytes(2, byteorder="big") + x)

def receive_nstp(sock):

    
    try:
        # sock.setblocking(0)
        sock.settimeout(0.5)
        expired= datetime.datetime.now() + datetime.timedelta(seconds=0.5)
        while True:
            header = sock.recv(2)
            if header:
                length, = struct.unpack('>H', header) 
                payload= sock.recv(length)
                break
            if expired > datetime.datetime.now():
                logging.debug("No response received")
                return 0
    except socket.timeout as e:
        logging.debug("Timeout exceeded")
        return 0
    except Exception as e:
        logging.debug("Got error in socket while receiving: {0}".format(e))
        return 0

    # # 1) Read the prefix
    # prefix = b""
    # while len(prefix) < 2:
    #     chunk = sock.recv(2)
    #     if not chunk:
    #         break
    #     prefix += chunk
    # if not prefix:
    #     logging.error("receive_ntsp(): failed to read NSTPMessage length prefix!")
    #     return 0
    # length = int.from_bytes(prefix, "big")
    
    # # 2) Read the payload
    # payload = b""
    # while len(payload) < length:
    #     chunk = sock.recv(length)
    #     if not chunk:
    #         break
    #     payload += chunk
    if not payload:
        logging.error("receive_ntsp(): failed to read NSTPMessage!")
        return 0
    
    # 3) Parse it
    nstp = nstp_v3_pb2.NSTPMessage()
    nstp.ParseFromString(payload)
    msg_type = nstp.WhichOneof("message_")
    logging.debug("receive_ntsp(): received {0} from the server, length: {1}".format(msg_type, length))
    if (options.debug):
        print(nstp)
    return nstp

def serialize_send_and_receive(msg, sock, msg_type=DECRYPTED_MESSAGE):
    nstp = nstp_v3_pb2.NSTPMessage()
    
    if msg_type == CLIENT_HELLO:
        nstp.client_hello.CopyFrom(msg)
    elif msg_type == SERVER_HELLO:
        nstp.server_hello.CopyFrom(msg)
    elif msg_type == ERROR_MESSAGE:
        nstp.error_message.CopyFrom(msg)
    elif msg_type == DECRYPTED_MESSAGE:
        global client_tx
        if client_tx == None:
            logging.error("serialize_send_and_receive(): Client TX key not generated!")
            exit(1)
            
        if (options.debug):
            logging.debug("serialize_send_and_receive(): encrypting message:")
            print(msg)
            
        nonce = randombytes(crypto_secretbox_NONCEBYTES)
        encrypted_bytes = crypto_secretbox(msg.SerializeToString(), nonce, client_tx)
        nstp.encrypted_message.ciphertext = encrypted_bytes
        nstp.encrypted_message.nonce = nonce
        bytes_to_send = nstp.SerializeToString()
    else:
        logging.error("serialize_send_and_receive(): Invalid msg_type!")
        exit(1)

    bytes_to_send = nstp.SerializeToString()
    logging.debug("serialize_send_and_receive(): sending {0} to the server, length: {1}".format(nstp.WhichOneof("message_"), len(bytes_to_send)))
    if (options.debug):
        print(nstp)
    sock.sendall(pack(bytes_to_send))
    
    # Here we shouldn't decrypt the message because we still don't know which type is it. We have to do it in each fuzz_...() function
    return receive_nstp(sock)

def decrypt_nstp(nstp):
    global client_rx
    
    ciphertext = nstp.encrypted_message.ciphertext
    nonce = nstp.encrypted_message.nonce
    
    try:
        plaintext = crypto_secretbox_open(ciphertext, nonce, client_rx)
    except:
        logging.error("decrypt_nstp(): decryption failed!")
    
    dec = nstp_v3_pb2.DecryptedMessage()
    try:
        dec.ParseFromString(plaintext)
    except:
        logging.error("decrypt_nstp(): ParseFromString() failed!")
    
    msg_type = dec.WhichOneof("message_")
    logging.debug("decrypt_nstp(): successfully decrypted {0} message from server".format(msg_type))
    if (options.debug):
        print(dec)
        
    return dec

def fuzz_client_hello(options):
    global client_public
    global server_address
    
    if options.major:
        logging.info("[ClientHello] major = {0}".format(options.major))
    if options.minor:
        logging.info("[ClientHello] minor = {0}".format(options.minor))
    if options.user_agent:
        logging.info("[ClientHello] user_agent = {0}".format(options.user_agent))
    if options.keys:
        logging.info("[ClientHello] client_public = {0} (loaded from \"./keys\")".format(client_public))
    else:
        logging.info("[ClientHello] client_public will be randomly generated")
        client_public = 0

    for i in range(0, options.rounds):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            
            client_hello = craft_client_hello(options.major, options.minor, options.user_agent, client_public, options.fuzz_field_len)
            client_hello_response = serialize_send_and_receive(client_hello, sock, msg_type=CLIENT_HELLO)   
            time.sleep(options.wait) 

        # TODO check ServerHello/Error
        # client_hello_response can be 0, if server terminated connection
    logging.info("[ClientHello] sent {0} ClientHello.".format(options.rounds))

def fuzz_auth_request(options):
    global client_public, client_private
    global server_address
    
    if options.username:
        logging.info("[AuthRequest] username = {0}".format(options.username))
    if options.password:
        logging.info("[AuthRequest] password = {0}".format(options.password))    
    
    if options.keys is None:
        logging.info("[AuthRequest] client keys will be randomly generated!")

    for i in range(0, options.rounds):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            # First, send a ClientHello to get the server public key
            generate_session_keys(sock, options.keys)
            # Then, craft a AuthenticationRequest and wrap it into DecryptedMessage
            auth_request = craft_auth_request(options.username, options.password, options.fuzz_field_len)
            decrypted_message = nstp_v3_pb2.DecryptedMessage()
            decrypted_message.auth_request.CopyFrom(auth_request)
            # Finally, serialize, encrypt the DecryptedMessage and wrap it into NSTPMessage
            auth_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

        # Decrypt from NSPTMessage
        if not auth_request_response:
            logging.error("fuzz_auth_request(): failed to receive response from the server, maybe it terminated the connection?")
            continue
        else:
            auth_request_response = decrypt_nstp(auth_request_response)
        # TODO check
        time.sleep(options.wait) 

    logging.info("[AuthRequest] sent {0} AuthRequest.".format(options.rounds))

def fuzz_ping_request(options):
    if options.data:
        logging.info("[PingRequest] data={0}".format(options.data))

    if options.algo:
        logging.info("[PingRequest] algorithm={0}".format(options.algo))

    if options.keys is None:
        logging.info("[PingRequest] client keys not provided, will be randomly generated!")

    if options.password is None:
        logging.info("[PingRequest] You must provide a password! Closing...")   
        exit(1)

    if options.username is None:
        logging.info("[PingRequest] You must provide a username! Closing...")   
        exit(1)

    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)
        # First generate the session keys and authenticate into the server
        generate_session_keys(sock, options.keys)
        auth_request = craft_auth_request(options.username, options.password, options.fuzz_field_len)
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        decrypted_message.auth_request.CopyFrom(auth_request)
        auth_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

        for i in range(0, options.rounds):
            ping_request = craft_ping_request(options.data, options.algo, options.fuzz_field_len)
            decrypted_message = nstp_v3_pb2.DecryptedMessage()
            decrypted_message.ping_request.CopyFrom(ping_request)
            ping_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

            # Decrypt from NSPTMessage
            if not ping_request_response:
                logging.error("fuzz_ping_request(): failed to receive response from the server, maybe it terminated the connection?")
                continue
            else:
                ping_request_response = decrypt_nstp(ping_request_response)
            # TODO check
            time.sleep(options.wait) 
            
    logging.info("[PingRequest] sent {0} PingRequest.".format(options.rounds))

def fuzz_load_request(options):
    global server_address

    if options.load_key:
        logging.info("[LoadRequest] Load Request key={options.load_key}")

    if options.load_public_key:
        logging.info("[LoadRequest] Load Request public={options.load_public_key}}")

    if options.keys is None:
        logging.info("[LoadRequest] client keys not provided, will be randomly generated!")

    if options.password is None:
        logging.info("[LoadRequest] You must provide a password! Closing...")   
        exit(1)

    if options.username is None:
        logging.info("[LoadRequest] You must provide a username! Closing...")   
        exit(1)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)
        # First generate the session keys and authenticate into the server
        generate_session_keys(sock, options.keys)
        auth_request=craft_auth_request(options.username, options.password, options.fuzz_field_len)
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        decrypted_message.auth_request.CopyFrom(auth_request)
        auth_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

        # parse load_public_key flag to boolean
        if options.load_public_key:
            public_key = options.load_public_key.lower() in ['true', '1', 't', 'y', 'yes']
        else:
            public_key = None

        for i in range(0, options.rounds):
            load_request = craft_load_request(options.load_key, public_key, options.fuzz_field_len)
            decrypted_message = nstp_v3_pb2.DecryptedMessage()
            decrypted_message.load_request.CopyFrom(load_request)
            load_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

            # Decrypt from NSPTMessage
            if not load_request_response:
                logging.error("fuzz_load_request(): failed to receive response from the server, maybe it terminated the connection?")
                continue
            else:
                load_request_response = decrypt_nstp(load_request_response)
            # TODO check
            time.sleep(options.wait) 
            
    logging.info("[LoadRequest] sent {0} LoadRequest.".format(options.rounds))

def fuzz_store_request(options):
    global server_address

    if options.store_key:
        logging.info("[StoreRequest] Store Request key={options.store_key}")

    if options.store_value:
        logging.info("[StoreRequest] Store Request public={options.store_value}}")
    
    if options.store_public_key:
        logging.info("[StoreRequest] Store Request key={options.store_public_key}")

    if options.keys is None:
        logging.info("[StoreRequest] client keys not provided, will be randomly generated!")

    if options.password is None:
        logging.info("[StoreRequest] You must provide a password! Closing...")   
        exit(1)

    if options.username is None:
        logging.info("[StoreRequest] You must provide a username! Closing...")   
        exit(1)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)
        # First generate the session keys and authenticate into the server
        generate_session_keys(sock, options.keys)
        auth_request=craft_auth_request(options.username, options.password, options.fuzz_field_len)
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        decrypted_message.auth_request.CopyFrom(auth_request)
        auth_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

        # parse load_public_key flag to boolean
        if options.store_public_key:
            public_key = options.store_public_key.lower() in ['true', '1', 't', 'y', 'yes']
        else:
            public_key = None

        for i in range(0, options.rounds):
            store_request = craft_store_request(options.store_key, options.store_value, public_key, options.fuzz_field_len)
            decrypted_message = nstp_v3_pb2.DecryptedMessage()
            decrypted_message.store_request.CopyFrom(store_request)
            store_request_response = serialize_send_and_receive(decrypted_message, sock, msg_type=DECRYPTED_MESSAGE)

            # Decrypt from NSPTMessage
            if not store_request_response:
                logging.error("fuzz_store_request(): failed to receive response from the server, maybe it terminated the connection?")
                continue
            else:
                store_request_response = decrypt_nstp(store_request_response)
            # TODO check
            time.sleep(options.wait) 
    
    logging.info("[StoreRequest] sent {0} StoreRequest.".format(options.rounds))

def generate_session_keys(sock, keys):
    global client_public, client_private
    global client_rx, client_tx
    
    if keys is None:
        # generate key pair everytime
        client_public, client_private = crypto_kx.crypto_kx_keypair()
        logging.debug("Generated new client key pair.")
        logging.debug("new client_public: {0}".format(client_public))
        logging.debug("new client_private: {0}".format(client_private))
    
    client_hello = craft_client_hello(3, 0, 'user_agent', client_public, options.fuzz_field_len)
    nstp_message_server_hello = serialize_send_and_receive(client_hello, sock, msg_type=CLIENT_HELLO)
    
    if nstp_message_server_hello !=0:
        server_public = nstp_message_server_hello.server_hello.public_key
    else:
        logging.error("Expecting ServerHello but nothing received. Server might have closed connection")
        exit(1)

    # Generate the session keys
    client_rx, client_tx = crypto_kx.crypto_kx_client_session_keys(client_public, client_private, server_public)


if __name__ == '__main__':    
    
    parser = argparse.ArgumentParser(description='NSTP Fuzzer')
    
    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument('--port',
                                help='NSTP server port. eg. --port 22300',
                                required = True,
                                type=int)                
    requiredGroup.add_argument('--ip',
                                required = True,
                                help='NSTP server IP. eg. --ip 192.168.1.2')
    
    # Option for logging level.
    parser.add_argument("--debug",
                        help = "Print out debug messages.",
                        action = "store_true",
                        default = False)

    # How many rounds do you want to fuzz?
    parser.add_argument("--rounds",
                        help = "How many rounds do you want to fuzz?",
                        type = int,
                        default = 10)

    # Options for the ClientHello.
    parser.add_argument("--client-hello",
                        help= 'Fuzz ClientHello messages. If none of the suboptions are provided, by default it will fuzz all the fields. On the other hand, if any suboption passed, it would be fixed to the value provided.',
                        action= "store_true",
                        default= None)
    parser.add_argument("--major", 
                        help='[ClientHello] Fixed major value to use. Otherwise, will be fuzzed.',
                        type=int,
                        default=None)       
    parser.add_argument("--minor", 
                        help='[ClientHello] Fixed minor value to use. Otherwise, will be fuzzed.',
                        type=int,
                        default=None)      
    parser.add_argument("--user_agent", 
                        help='[ClientHello] Fixed user agent to use. Otherwise, will be fuzzed.',
                        default=None)               

    # Options for the AuthenticationRequest.
    parser.add_argument("--auth-request",
                        help= 'Fuzz AuthenticationRequest messages. If none of the suboptions are provided, by default it will fuzz all the fields. On the other hand, if any suboption passed, it would be fixed to the value provided.',
                        action= "store_true",
                        default= None)
    parser.add_argument("--user", 
                        help='[AuthenticationRequest] Fixed user to use. Otherwise, will be fuzzed.',
                        default=None) 
    parser.add_argument("--pwd", 
                        help='[AuthenticationRequest] Fixed password to use. Otherwise, will be fuzzed.',
                        default=None)     

    # Options for the PingRequest.
    parser.add_argument("--ping-request",
                    help= 'Fuzz PingRequest messages. If none of the suboptions are provided, by default it will fuzz all the fields. On the other hand, if any suboption passed, it would be fixed to the value provided.',
                    action= "store_true",
                    default= None)
    parser.add_argument("--data", 
                    help="""[PingRequest] Fixed data IN BYTES to use. Otherwise, will be fuzzed. e.g. "b'\x02\xe67\x00\xb8\'\xeb\xff'"  """,
                    default=None) 
    parser.add_argument("--algo", 
                    help="[PingRequest] Fixed algorithm to use. Otherwise, will be fuzzed. 0-IDENTITY, 1-SHA-256 and 2-SHA-512",
                    type=int,
                    default=None)                  
    
    # Options for the LoadRequest.
    parser.add_argument("--load-request",
                    help= 'Fuzz LoadRequest messages. If none of the suboptions are provided, by default it will fuzz all the fields. On the other hand, if any suboption passed, it would be fixed to the value provided.',
                    action= "store_true",
                    default= None)
    parser.add_argument("--load-key", 
                        help='[LoadRequest] Fixed key to use. Otherwise, will be fuzzed.',
                        default=None)    
    parser.add_argument("--load-public-key", 
                        help='[LoadRequest] Fixed boolean field to use. Otherwise, will be fuzzed. e.g. true/t or false/f',
                        default=None)  

    # Options for the StoreRequest.
    parser.add_argument("--store-request",
                    help= 'Fuzz StoreRequest messages. If none of the suboptions are provided, by default it will fuzz all the fields. On the other hand, if any suboption passed, it would be fixed to the value provided.',
                    action= "store_true",
                    default= None)
    parser.add_argument("--store-key", 
                        help='[StoreRequest] Fixed key to use. Otherwise, will be fuzzed.',
                        default=None)
    parser.add_argument("--store-value", 
                        help='[StoreRequest] Fixed value to use. Otherwise, will be fuzzed.',
                        default=None)    
    parser.add_argument("--store-public-key", 
                        help='[StoreRequest] Fixed boolean field to use. Otherwise, will be fuzzed. e.g. true/t or false/f',
                        default=None)

    # Parse required arguments for AuthenticationRequest, PingRequest, StoreRequest and LoadRequest
    parser.add_argument("--keys", 
                        help='[ClientHello/AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Load key pairs from file "./keys". If file doesn\'t exist, then a keypair is generated and stored in "./keys".',
                        action = "store_true",
                        default=None) 
    parser.add_argument("--username", 
                        help='[AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Valid user to log into the server.',
                        default=None)
    parser.add_argument("--password", 
                        help='[AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Valid password to log into the server.',
                        default=None)
    parser.add_argument("--fuzz_field_len", 
                    help='[ClientHello/AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] maximum length for variable length data, default is 1024',
                    default=1024)           
    parser.add_argument("--wait",
                        help='Time in seconds between messages. By default, this time is 0 second',
                        type=float,
                        default=0.0
                        )    

    options = parser.parse_args()

    # Setting logging level
    if (options.debug):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        
    # IP and port are global so that send() function can obtain them easily
    global server_address
    server_address=(options.ip, options.port)

    global client_public, client_private
    if (options.keys):
        # load from "./keys"
        try:
            f = open("./keys", "rb")
            client_public = f.read(32)
            client_private = f.read(32)
            logging.debug("Loaded client key pair from file \"./keys\".")
            logging.debug("client_public: {0}".format(client_public))
            logging.debug("client_private: {0}".format(client_private))
        except FileNotFoundError:
            logging.debug("\"./keys\" does not exist!")
            
            try:
                client_public, client_private = crypto_kx.crypto_kx_keypair()
                f = open("./keys", "wb")
                f.write(client_public)
                f.write(client_private)
                logging.debug("Generated client key pair and stored in file \"./keys\".")
                logging.debug("client_public: {0}".format(client_public))
                logging.debug("client_private: {0}".format(client_private))
                f.close()
            except Exception as e:
                logging.error("Error generating and saving keypair: {e}")
       

    if options.client_hello:
        fuzz_client_hello(options)
    elif options.auth_request:
        fuzz_auth_request(options)
    elif options.ping_request:
        fuzz_ping_request(options)
    elif options.load_request:
        fuzz_load_request(options)
    elif options.store_request:
        fuzz_store_request(options)
    else:
        logging.error("No message selected. Closing.")
        exit(1)