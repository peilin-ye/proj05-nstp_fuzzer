import ast
import utils.nstp_v3_pb2 as nstp_v3_pb2
import pytest
import utils.ProtoCrafter as pc

def test_craft_load_request():
	crafted_load = pc.craft_load_request(key="test_key", is_public=True)
	assert crafted_load.key == "test_key"
	assert crafted_load.public == True

def test_craft_store_request():
	crafted_store = pc.craft_store_request(key="test_key", value=b'test_value', is_public=True)
	assert crafted_store.key == "test_key"
	assert crafted_store.value == b'test_value'
	assert crafted_store.public == True

def test_craft_ping_request():
	crafted_ping = pc.craft_ping_request(data=b'test_data', algorithm=2)
	assert crafted_ping.data == b'test_data'
	assert crafted_ping.hash_algorithm == 2

def test_craft_auth_request():
	crafted_auth = pc.craft_auth_request(username="test_username", password="test_password")
	assert crafted_auth.username == "test_username"
	assert crafted_auth.password == "test_password"

def test_craft_client_hello():
	crafted_hello = pc.craft_client_hello(major=3, minor=1, user_agent="test_agent", public_key=b'test_key')
	assert crafted_hello.major_version == 3
	assert crafted_hello.minor_version == 1
	assert crafted_hello.user_agent == "test_agent"
	assert crafted_hello.public_key == b'test_key'

def test_craft_client_hello_random():
	crafted_hello = pc.craft_client_hello()
	print("random client hello example")
	print("major version {}".format(crafted_hello.major_version))
	print("minor version {}".format(crafted_hello.minor_version))
	print("user agent {}".format(crafted_hello.user_agent))
	print("public key {}".format(crafted_hello.public_key))


def test_craft_load_request_random():
	crafted_load = pc.craft_load_request()
	print("random load request example")
	print("load key {}".format(crafted_load.key))
	print("load public {}".format(crafted_load.public))

def test_craft_store_request_random():
	crafted_store = pc.craft_store_request()
	print("random store request example")
	print("store key {}".format(crafted_store.key))
	print("store value {}".format(crafted_store.value))
	print("store public {}".format(crafted_store.public))

def test_craft_ping_request_random():
	crafted_ping = pc.craft_ping_request()
	print("random ping request example")
	print("ping data {}".format(crafted_ping.data))
	print("ping hash_algorithm {}".format(crafted_ping.hash_algorithm))

def test_craft_auth_request_random():
	crafted_auth = pc.craft_auth_request()
	print("random auth request example")
	print("auth username {}".format(crafted_auth.username))
	print("auth password {}".format(crafted_auth.password))
