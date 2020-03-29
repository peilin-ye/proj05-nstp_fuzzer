import ast
import utils.nstp_v3_pb2 as nstp_v3_pb2

# If value provided remains None -> Just put a random value :) 

def random():
    # TODO This is just a place holder.
    return 42

def craft_client_hello(major=None, minor=None, user_agent=None, public_key=None):
    """
    Returns an NSTPMessage containing a ClientHello.
    If not specified in parameters, field values are randomly generated.
    
    :param major: int
    :param minor: int
    :param user_agent: string
    :param public_key: bytes
    :rtype: NSTPMessage
    """
   
    client_hello = nstp_v3_pb2.ClientHello()
    
    # TODO replace random() functions with real rand(), according to field type
    client_hello.major_version = random() if (major is None) else major 
    client_hello.minor_version = random() if (minor is None) else minor
    client_hello.user_agent = str(random()) if (user_agent is None) else user_agent
    client_hello.public_key = str(random()).encode() if (public_key is None) else public_key

    return client_hello

def craft_auth_request(username=None, password=None):

    # TODO replace random() functions with real rand(), according to field type
    if username is None:
        username=random()

    if password is None:
        password=random()

    # TODO Now that we have all the values, Serialize to protobuf!
    proto_auth_request= nstp_v3_pb2.AuthenticationRequest()

    return proto_auth_request

def craft_ping_request(data=None, algorithm=None):
    # TODO replace random() functions with real rand(), according to field type
    
    if data is None:
        data=random()
    else:
        # literal_eval takes the string "b'\x01....'" as bytes
        data= ast.literal_eval(data)

    if algorithm is None:
        algorithm=random()
    

    # TODO Now that we have all the values, Serialize to protobuf!
    proto_ping_request= nstp_v3_pb2.PingRequest()

    return proto_ping_request

def craft_store_request(key=None, value=None, is_public=None):
    # TODO replace random() functions with real rand(), according to field type
    if key is None:
        key=random()

    if value is None:
        value=random()
    else:
        # literal_eval takes the string "b'\x01....'" as bytes
        value=ast.literal_eval(value)

    if is_public is None:
        is_public=random()

    # TODO Now that we have all the values, Serialize to protobuf!
    proto_store_request= nstp_v3_pb2.StoreRequest()

    return proto_store_request

def craft_load_request(key=None, is_public=None):
    pass
    # TODO