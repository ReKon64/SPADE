# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_dns_dig(self):
    """
    Perform DNS queries using dig.
    1. AXFR Zone Transfer
    2. ANY Query
    3. If RDP NTLM info is present, attempt to resolve those names

    Returns:
        dict: Results of DNS queries
    """
    port = self.options["current_port"]["port_id"]
    host = self.options["current_port"]["host"]
    port_obj = self.options["current_port"].get("port_obj", {})
    findings = port_obj.get("scripts", {}) if port_obj else {}

    results = {
        "axfr": None,
        "any": None,
        "rdp_ntlm_resolves": {}
    }

    # AXFR Zone Transfer
    try:
        axfr_cmd = ["dig", "@"+host, "axfr"]
        axfr_result = subprocess.run(axfr_cmd, capture_output=True, text=True, timeout=10)
        results["axfr"] = axfr_result.stdout
    except Exception as e:
        results["axfr"] = f"Error: {e}"

    # ANY Query
    try:
        any_cmd = ["dig", host, "any"]
        any_result = subprocess.run(any_cmd, capture_output=True, text=True, timeout=10)
        results["any"] = any_result.stdout
    except Exception as e:
        results["any"] = f"Error: {e}"

    # If RDP NTLM info is present, try to resolve those names
    rdp_info = findings.get("rdp-ntlm-info", {})
    if isinstance(rdp_info, dict):
        names_to_resolve = []
        for key in [
            "DNS_Domain_Name", "DNS_Computer_Name", "DNS_Tree_Name",
            "NetBIOS_Domain_Name", "NetBIOS_Computer_Name", "Target_Name"
        ]:
            value = rdp_info.get(key)
            if value and value not in names_to_resolve:
                names_to_resolve.append(value)
        for name in names_to_resolve:
            try:
                resolve_cmd = ["dig", name]
                resolve_result = subprocess.run(resolve_cmd, capture_output=True, text=True, timeout=10)
                results["rdp_ntlm_resolves"][name] = resolve_result.stdout
            except Exception as e:
                results["rdp_ntlm_resolves"][name] = f"Error: {e}"

    return results