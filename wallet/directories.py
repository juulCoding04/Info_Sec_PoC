import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'storage', 'credentials')
ISSUERS_FILE = os.path.join(BASE_DIR, 'data', 'trusted_issuers.json')
INCOMING_DIR = os.path.join(BASE_DIR, 'data', 'issued_credentials')
PRESENTATION_DIR = os.path.join(BASE_DIR, 'data', 'presentations')
DEVICE_KEY_DIR = os.path.join(os.path.dirname(__file__), 'device_keys')
REVOCATION_FILE = os.path.join(BASE_DIR, 'data', 'revocation_list.json')
PIN_FILE = os.path.join(os.path.dirname(__file__), 'wallet_pin.json')
