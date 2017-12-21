from __future__ import print_function, unicode_literals
from base64 import b64encode,b64decode
import requests
import random
import string
from Crypto.Hash import SHA, HMAC
from requests.auth import HTTPDigestAuth
import argparse

# Key used for generated the HMAC signature
secret_key = "ZmVay1EQVFOaZhwQ4Kv81ypLAZNczV9sG4KkseXWn1NEk6cXmPKO/MCa9sryslvLCFMnNe4Z4CPXzToowvhHvA=="
device_id_charset = string.ascii_uppercase + string.digits + string.ascii_lowercase

# Turn off ssl warnings
requests.packages.urllib3.disable_warnings()


def create_device_id():
    return "".join(random.SystemRandom().choice(device_id_charset) for _ in range(16))


def create_signature(key, to_sign):
    sign = HMAC.new(key, to_sign, SHA)
    return str(b64encode(sign.hexdigest().encode()))


def get_device_spec_json(config):
    return {
        "device_name": "philips_android_tv_python_client",
        "device_os": "Android",
        "app_name": "PythonClient",
        "type": "native",
        "app_id": config["application_id"],
        "id": config["device_id"]
    }


def pair(config):
    config.update(dict(
        application_id="app.id",
        device_id=create_device_id())
    )

    data = {
        "scope": ["read", "write", "control"],
        "device": get_device_spec_json(config)
    }

    print("Starting pairing request")
    r = requests.post("https://{}:1926/6/pair/request".format(config["address"]),
                      json=data, verify=False)

    response = r.json()
    auth_timestamp = response["timestamp"]
    config["auth_key"] = response["auth_key"]

    pin = input("Enter onscreen passcode: ")

    auth = {
        "auth_AppId": "1",
        "pin": str(pin),
        "auth_timestamp": auth_timestamp,
        "auth_signature": create_signature(b64decode(secret_key), str(auth_timestamp).encode() + str(pin).encode())
    }

    grant_request = {
        "auth": auth,
        "device": get_device_spec_json(config)
    }

    print("Attempting to pair")
    r = requests.post(
        url="https://{}:1926/6/pair/grant".format(config["address"]),
        json=grant_request,
        verify=False,
        auth=HTTPDigestAuth(config["device_id"], config["auth_key"])
    )

    print(r.json())
    print("Username for subsequent calls is: " + config["device_id"])
    print("Password for subsequent calls is: " + config["auth_key"])


def get_command(config):
    r = requests.get(
        url="https://{}:1926/".format(config["address"], config["path"]),
        verify=False,
        auth=HTTPDigestAuth(config["device_id"], config["auth_key"])
    )

    print(r)
    print(r.url)
    print(r.text)
    print(r.json())


def post_command(config):
    r = requests.post(
        url="https://{}:1926/{}".format(config["address"], config["path"]),
        json=config["body"],
        verify=False,
        auth=HTTPDigestAuth(config["device_id"], config["auth_key"])
    )
    print(r)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Control a HuaFan WifiSwitch.")
    parser.add_argument("--host", dest="host", help="Host/address of the TV")
    parser.add_argument("--user", dest="user", help="Username")
    parser.add_argument("--pass", dest="password", help="Password")
    parser.add_argument("command",  help="Command to run (pair/get_volume/get/standby)")
    return parser.parse_args()


def main():
    args = parse_arguments()

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




