from base64 import b64encode,b64decode
import requests
import random
import string
from Crypto.Hash import SHA, HMAC
from requests.auth import HTTPDigestAuth
import argparse

# Key used for generated the HMAC signature
secret_key = "ZmVay1EQVFOaZhwQ4Kv81ypLAZNczV9sG4KkseXWn1NEk6cXmPKO/MCa9sryslvLCFMnNe4Z4CPXzToowvhHvA=="

device_id_char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase
device_id_char_length = 16


def create_device_id():
    return "".join(random.SystemRandom().choice(device_id_char_set) for _ in range(device_id_char_length))


def create_signature(psk, to_sign):
    sign = HMAC.new(psk, to_sign, SHA)
    return b64encode(sign.hexdigest())


def get_device_spec_json(config):
    return {
        "device_name": "philips_android_tv",
        "device_os": "Android",
        "app_name": "philips_android_tv",
        "type": "native",
        "app_id": config["application_id"],
        "id": config["device_id"]
    }


def pair(config):
    config["application_id"] = "philips_android_tv"
    config["device_id"] = create_device_id()
    data = {"scope": ["read", "write", "control"], "device": get_device_spec_json(config)}
    print("Starting pairing request")
    r = requests.post("https://" + config["address"] + ":1926/6/pair/request", json=data, verify=False)
    response = r.json()
    auth_timestamp = response["timestamp"]
    config["auth_key"] = response["auth_key"]

    pin = input("Enter onscreen passcode: ")

    auth = {"auth_AppId": "1", "pin": str(pin), "auth_timestamp": auth_timestamp,
            "auth_signature": create_signature(b64decode(secret_key), str(auth_timestamp) + str(pin))}

    grant_request = {"auth": auth, "device": get_device_spec_json(config)}

    print("Attempting to pair")
    r = requests.post("https://" + config["address"] +":1926/6/pair/grant", json=grant_request, verify=False,auth=HTTPDigestAuth(config["device_id"], config["auth_key"]))
    print(r.json())
    print("Username for subsequent calls is: " + config["device_id"])
    print("Password for subsequent calls is: " + config["auth_key"])


def get_command(config):
    r = requests.get("https://" + config["address"] + ":1926/" + config["path"], verify=False,auth=HTTPDigestAuth(config["device_id"], config["auth_key"]))
    print(r)
    print(r.url)
    print(r.text)
    print(r.json())


def post_command(config):
    r = requests.post("https://" + config["address"] + ":1926/" + config["path"], json=config["body"], verify=False,auth=HTTPDigestAuth(config["device_id"], config["auth_key"]))
    print(r)


def main():
    parser = argparse.ArgumentParser(description="Control a Philips Android TV on your LAN.")
    parser.add_argument("--host", dest="host", help="Host/address of the TV")
    parser.add_argument("--user", dest="user", help="Username")
    parser.add_argument("--pass", dest="password", help="Password")
    parser.add_argument("command",  help="Command to run (pair/get_volume/get/standby)")

    args = parser.parse_args()

    config = {"address": args.host}

    if args.command == "pair":
        pair(config)

    config["device_id"] = args.user
    config["auth_key"] = args.password

    if args.command == "get_volume":
        config["path"] = "6/audio/volume"
        get_command(config)

    if args.command == "get":
        # All working commands
        config["path"] = "6/channeldb/tv"
        config["path"] = "6/applications"
        config["path"] = "6/ambilight/mode"
        config["path"] = "6/ambilight/topology"
        config["path"] = "6/recordings/list"
        config["path"] = "6/powerstate"
        config["path"] = "6/ambilight/currentconfiguration"
        config["path"] = "6/channeldb/tv/channelLists/all"
        config["path"] = "6/system/epgsource"
        config["path"] = "6/system"
        config["path"] = "6/system/storage"
        config["path"] = "6/system/timestamp"
        config["path"] = "6/menuitems/settings/structure"
        config["path"] = "6/ambilight/cached"
      
        get_command(config)

    if args.command == "standby":
        config["path"] = "6/input/key"
        config["body"] = {"key": "Standby"}
        post_command(config)

main()
