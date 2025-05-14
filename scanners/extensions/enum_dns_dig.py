# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_dns_dig(self):
    """
    Perform DNS queries using dig.
    1. AXFR Zone Transfer
    2. ANY Query
    3. ?

    Returns:
        Nothing. Results appended to the NMAP scan file.
    """
    port = self.options["current_port"]["port_id"]
    host = self.options["current_port"]["host"]

    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        json_output = tmp_file.name

    try: 
        zonetransfer = f"dig -axfr {host}"

    except:
        print("pylance")