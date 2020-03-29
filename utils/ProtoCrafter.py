import ast
import utils.nstp_v3_pb2 as nstp_v3_pb2

# If value provided remains None -> Just put a random value :) 

def random():
    # TODO This is just a place holder.
    return 42

def craft_client_hello(major=None, minor=None, user_agent=None, public_key=None):
    client_hello = nstp_v3_pb2.ClientHello()
    
    # TODO replace random() functions with real rand(), according to field type
    client_hello.major_version = random() if (major is None) else major 
    client_hello.minor_version = random() if (minor is None) else minor
    client_hello.user_agent = str(random()) if (user_agent is None) else user_agent
    client_hello.public_key = str(random()).encode() if (public_key is None) else public_key

    return client_hello

def craft_auth_request(username=None, password=None):
    auth_request = nstp_v3_pb2.AuthenticationRequest()

    # TODO replace random() functions with real rand(), according to field type
    auth_request.username = str(random()) if (username is None) else username
    auth_request.password = str(random()) if (password is None) else password

    return auth_request

def craft_ping_request(data=None, algorithm=None):
    ping_request = nstp_v3_pb2.PingRequest()
    
    # TODO replace random() functions with real rand(), according to field type
    ping_request.data = str(random()).encode() if (data is None) else ast.literal_eval(data)
    ping_request.hash_algorithm = random() if (algorithm is None) else algorithm

    return ping_request

def craft_store_request(key=None, value=None, is_public=None):
    store_request = nstp_v3_pb2.StoreRequest()
    
    # TODO replace random() functions with real rand(), according to field type
    store_request.key = str(random()) if (key is None) else key
    store_request.value = str(random()).encode() if (value is None) else ast.literal_eval(value)
    store_request.is_public = bool(random()) if (is_public is None) else is_public

    return store_request

def craft_load_request(key=None, is_public=None):
    load_request = nstp_v3_pb2.LoadRequest()

    # TODO replace random() functions with real rand(), according to field type
    load_request.key = str(random()) if (key is None) else key
    load_request.is_public = bool(random()) if (is_public is None) else is_public