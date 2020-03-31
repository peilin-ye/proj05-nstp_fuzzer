import utils.nstp_v3_pb2 as nstp_v3_pb2
import random as rand
import string
import secrets

def random(attribute_type=None):
    length = rand.randint(0,512)
    if attribute_type == 'str':
        letters = string.printable  
        return ''.join(rand.choice(letters) for i in range(length))
    elif attribute_type == 'int':
        return rand.randint(0,pow(2,32) -1)
    elif attribute_type == 'bool':
        return rand.randint(0,1) == 1
    elif attribute_type == 'hash_algorithm':
        return rand.randint(0,2)
    else:
        return secrets.token_bytes(length)

def craft_client_hello(major=None, minor=None, user_agent=None, public_key=None):
    client_hello = nstp_v3_pb2.ClientHello()
    client_hello.major_version = random('int') if (major is None) else major 
    client_hello.minor_version = random('int') if (minor is None) else minor
    client_hello.user_agent = random('str') if (user_agent is None) else user_agent
    client_hello.public_key = random('str').encode() if (public_key is None) else public_key

    return client_hello

def craft_auth_request(username=None, password=None):
    auth_request = nstp_v3_pb2.AuthenticationRequest()
    auth_request.username = random('str') if (username is None) else username
    auth_request.password = random('str') if (password is None) else password

    return auth_request

def craft_ping_request(data=None, algorithm=None):
    ping_request = nstp_v3_pb2.PingRequest()
    ping_request.data = random() if (data is None) else data
    ping_request.hash_algorithm = random('hash_algorithm') if (algorithm is None) else algorithm

    return ping_request

def craft_store_request(key=None, value=None, is_public=None):
    store_request = nstp_v3_pb2.StoreRequest()
    store_request.key = random('str') if (key is None) else key
    store_request.value = random() if (value is None) else value
    store_request.public = random('bool') if (is_public is None) else is_public

    return store_request

def craft_load_request(key=None, is_public=None):
    load_request = nstp_v3_pb2.LoadRequest()
    load_request.key = random('str') if (key is None) else key
    load_request.public = random('bool') if (is_public is None) else is_public

    return load_request