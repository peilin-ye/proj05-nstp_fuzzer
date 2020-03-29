import argparse, socket, struct, logging
import utils.ProtoCrafter
import nacl.utils
import utils.nstp_v3_pb2 as nstp_v3_pb2
from utils.ProtoCrafter import craft_client_hello, craft_auth_request # TODO Add missing imports here 
import nacl.bindings.crypto_kx as crypto_kx
from nacl.bindings.crypto_secretbox import crypto_secretbox_open, crypto_secretbox, crypto_secretbox_NONCEBYTES 
from nacl.bindings.randombytes import randombytes

CLIENT_HELLO      = 1   # client_hello = 1;
SERVER_HELLO      = 2   # server_hello = 2;
ERROR_MESSAGE     = 3   # error_message = 3;
ENCRYPTED_MESSAGE = 4   # encrypted_message = 4;

def pack(x):
    return (len(x).to_bytes(2, byteorder="big") + x)

def receive_nstp(sock):
    # 1) Read the prefix
    prefix = b""
    while len(prefix) < 2:
        chunk = sock.recv(2)
        if not chunk:
            break
        prefix += chunk
    if not prefix:
        logging.error("receive_ntsp(): failed to read NSTPMessage length prefix!")
        return 0
    length = int.from_bytes(prefix, "big")
    
    # 2) Read the payload
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length)
        if not chunk:
            break
        payload += chunk
    if not payload:
        logging.error("receive_ntsp(): failed to read NSTPMessage!")
        return 0
    
    # 3) Parse it
    nstp = nstp_v3_pb2.NSTPMessage()
    nstp.ParseFromString(payload)
    msg_type = nstp.WhichOneof("message_")
    logging.debug("receive_ntsp(): received {0} from the server, length: {1}".format(msg_type, length))
    return nstp

def serialize_send_and_receive(msg, sock, msg_type=ENCRYPTED_MESSAGE):
    nstp = nstp_v3_pb2.NSTPMessage()
    
    if msg_type == CLIENT_HELLO:
        nstp.client_hello.CopyFrom(msg)
    elif msg_type == SERVER_HELLO:
        nstp.server_hello.CopyFrom(msg)
    elif msg_type == ERROR_MESSAGE:
        nstp.error_message.CopyFrom(msg)
    elif msg_type == ENCRYPTED_MESSAGE:
        global client_tx
        if client_tx == None:
            logging.error("serialize_send_and_receive(): Client TX key not generated!")
            exit(1)
        nonce = randombytes(crypto_secretbox_NONCEBYTES)
        encrypted_bytes = crypto_secretbox(bytes_to_send, nonce, client_tx)
        nstp.encrypted_message.ciphertext = encrypted_bytes
        nstp.encrypted_message.nonce = nonce
        bytes_to_send = nstp.SerializeToString()
    else:
        logging.error("serialize_send_and_receive(): Invalid msg_type!")
        exit(1)

    bytes_to_send = nstp.SerializeToString()
    logging.debug("serialize_send_and_receive(): sending {0} to the server, length: {1}".format(nstp.WhichOneof("message_"), len(bytes_to_send)))
    sock.sendall(pack(bytes_to_send))
    
    # Here we shouldn't decrypt the message because we still don't know which type is it. We have to do it in each fuzz_...() function
    return receive_nstp(sock)

def fuzz_client_hello(options):
    if options.major:
        logging.info("[ClientHello] major={options.major}")
    if options.minor:
        logging.info("[ClientHello] minor={options.minor}")
    if options.user_agent:
        logging.info("[ClientHello] user_agent={options.user_agent}")
    if options.public_key:
        logging.info("[ClientHello] public_key={options.public_key}")

    global server_address

    for i in range(0, options.rounds):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            
            client_hello = craft_client_hello(options.major, options.minor, options.user_agent, options.public_key)
            clien_hello_response = serialize_send_and_receive(client_hello, sock, msg_type=CLIENT_HELLO)    

        # TODO check ServerHello/Error

def fuzz_auth_request(options):
    if options.username:
        logging.info("[AuthRequest] username={options.username}")
    if options.password:
        logging.info("[AuthRequest] password={options.password}")    
    
    if options.public_key is None:
        logging.info("[AuthRequest] You must provide a public_key! Closing...")   
        exit(1)

    # TODO may be, this have to be in a loop? I mean, to send a client hello per AuthRequest? We'd have to adjust it as we test the servers
    generate_session_keys(options.public_key)

    for i in range(0, options.rounds):
        auth_request=craft_auth_request(options.username, options.password)

        auth_request_response=serialize_send_and_receive(auth_request)

        # TODO decrypt and check AuthResponse/Error
        global client_rx

def fuzz_ping_request(options):
    if options.data:
        logging.info("[PingRequest] username={options.data}")

    if options.algo:
        logging.info("[PingRequest] algorithm={options.algo}")

    if options.public_key is None:
        logging.info("[PingRequest] You must provide a public_key! Closing...")   
        exit(1)

    if options.password is None:
        logging.info("[PingRequest] You must provide a password! Closing...")   
        exit(1)

    if options.username is None:
        logging.info("[PingRequest] You must provide a username! Closing...")   
        exit(1)

    # First we have to generate the session keys and authenticate into the server
    generate_session_keys(options.public_key)
    auth_request=craft_auth_request(options.username, options.password)

    # TODO decrypt and check AuthResponse/Error
    global client_rx

    for i in range(0, options.rounds):
        ping_request=craft_ping_request(options.data, options.algo)

        ping_request_response=serialize_send_and_receive(ping_request)

        # TODO decrypt and check PingResponse/Error

def fuzz_load_request(options):
    # TODO. See PingRequest 
    pass

def fuzz_store_request(options):
    # TODO. See PingRequest 
    pass

def generate_session_keys(public_key):
    client_hello=craft_client_hello(1, 1, 'user_agent_test', public_key)
    nstp_message_server_hello= serialize_send_and_receive(client_hello, encrypt=False)
    server_public_key=nstp_message_server_hello.server_hello.public_key

    # Generate the session keys
    global client_public, client_private
    global client_rx, client_tx
    client_rx, client_tx = crypto_kx.crypto_kx_client_session_keys(client_public, client_private, server_public_key)


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
    parser.add_argument("--public-key", 
                        help='[ClientHello/AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Valid public key to exchange with server.',
                        default=None) 
    parser.add_argument("--username", 
                        help='[AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Valid user to log into the server.',
                        default=None)
    parser.add_argument("--password", 
                        help='[AuthenticationRequest/PingRequest/StoreRequest/LoadRequest] Valid password to log into the server.',
                        default=None)          

    options= parser.parse_args()

    # Setting logging level
    if (options.debug):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # IP and port are global so that send() function can obtain them easily
    global server_address
    server_address=(options.ip, options.port)

    global client_public, client_private
    client_public, client_private= crypto_kx.crypto_kx_keypair()

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
        exit(0)