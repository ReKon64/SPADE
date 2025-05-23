# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_dns_dig(self, plugin_results=None):
    """
    Perform DNS queries using dig.
    1. AXFR Zone Transfer
    2. ANY Query
    3. If host-level info is present (domain, computername, hostname, etc.), attempt to resolve those names

    Returns:
        dict: { "cmd": [list of commands], "results": { ... } }
    """
    if plugin_results is None:
        plugin_results = {}
        
    port = self.options["current_port"]["port_id"]
    host = self.options["current_port"]["host"]
    host_json = self.options["current_port"].get("host_json", {})

    results = {
        "axfr": None,
        "any": None,
        "resolves": {}
    }
    cmds = []

    # AXFR Zone Transfer
    try:
        axfr_cmd = ["dig", "@"+host, "axfr"]
        cmds.append(" ".join(axfr_cmd))
        axfr_result = subprocess.run(axfr_cmd, capture_output=True, text=True, timeout=10)
        results["axfr"] = axfr_result.stdout
    except Exception as e:
        results["axfr"] = f"Error: {e}"

    # ANY Query
    try:
        any_cmd = ["dig", host, "any"]
        cmds.append(" ".join(any_cmd))
        any_result = subprocess.run(any_cmd, capture_output=True, text=True, timeout=10)
        results["any"] = any_result.stdout
    except Exception as e:
        results["any"] = f"Error: {e}"

    # Collect names to resolve from host-level info
    names_to_resolve = []
    for key in [
        "domain", "computername", "hostname",
        "DNS_Domain_Name", "DNS_Computer_Name", "DNS_Tree_Name",
        "NetBIOS_Domain_Name", "NetBIOS_Computer_Name", "Target_Name"
    ]:
        value = host_json.get(key)
        if value and value not in names_to_resolve and value != "unknown":
            names_to_resolve.append(value)

    # I'm honestly not sure what I wanted to achieve with writing this.
    for name in names_to_resolve:
        try:
            logging.debug(f"[*] Trying to resolve {name}")
            resolve_cmd = ["dig", name]
            cmds.append(" ".join(resolve_cmd))
            resolve_result = subprocess.run(resolve_cmd, capture_output=True, text=True, timeout=10)
            results["resolves"][name] = resolve_result.stdout
        except Exception as e:
            results["resolves"][name] = f"Error: {e}"

    logging.debug(f"enum_dns_dig results: {results}")
    return {"cmd": cmds, "results": results}

enum_dns_dig.depends_on = ["scan_tcp_scanner"]