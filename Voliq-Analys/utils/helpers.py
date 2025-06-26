import re

def is_valid_hex_address(address):
    return re.match(r"^0x[a-fA-F0-9]+$", address) is not None
