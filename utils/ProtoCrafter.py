import utils.nstp_v3_pb2 as nstp_v3_pb2
import random as rand
import string
import ast
import secrets

def random(attribute_type=None, fuzz_len=None):
    length = rand.randint(0, 1024) if (fuzz_len is None) else int(fuzz_len)
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

def craft_client_hello(major=None, minor=None, user_agent=None, client_public=None, length=None):
    client_hello = nstp_v3_pb2.ClientHello()
    client_hello.major_version = random('int', length) if (major is None) else major 
    client_hello.minor_version = random('int', length) if (minor is None) else minor
    client_hello.user_agent = random('str', length) if (user_agent is None) else user_agent
    client_hello.public_key = random(fuzz_len=length) if (not client_public) else client_public

    return client_hello

def craft_auth_request(username=None, password=None, length=None):
    auth_request = nstp_v3_pb2.AuthenticationRequest()
    auth_request.username = random('str', length) if (username is None) else username
    auth_request.password = random('str', length) if (password is None) else password

    return auth_request

def craft_ping_request(data=None, algorithm=None, length=None):
    ping_request = nstp_v3_pb2.PingRequest()
    ping_request.data = random(fuzz_len=length) if (data is None) else ast.literal_eval(data)
    ping_request.hash_algorithm = random('hash_algorithm', length) if (algorithm is None) else algorithm

    return ping_request

def craft_store_request(key=None, value=None, is_public=None, length=None):
    store_request = nstp_v3_pb2.StoreRequest()
    store_request.key = random('str', length) if (key is None) else key
    store_request.value = random(fuzz_len=length) if (value is None) else ast.literal_eval(value)  
    store_request.public = random('bool', length) if (is_public is None) else is_public

    return store_request

def craft_load_request(key=None, is_public=None, length=None):
    load_request = nstp_v3_pb2.LoadRequest()
    load_request.key = random('str', length) if (key is None) else key
    load_request.public = random('bool', length) if (is_public is None) else is_public

    return load_request