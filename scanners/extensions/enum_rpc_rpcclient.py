from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_rpc_rpcclient(self):
    """
    Enumerate RPC info using rpcclient with a null session.
    Attempts:
      - Enumerate users
      - Enumerate shares
      - Enumerate domains
      - Enumerate groups
      - Null bind (srvinfo)
    Returns:
        dict: Results of rpcclient enumeration
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    results = {}

    # Enumerate users
    try:
        cmd = f"rpcclient -U '' -N {host} -p {port} -c 'enumdomusers'"
        users = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        results["users"] = users.stdout if users.returncode == 0 else users.stderr
    except Exception as e:
        results["users"] = f"Error: {e}"

    # Enumerate shares
    try:
        cmd = f"rpcclient -U '' -N {host} -p {port} -c 'netshareenumall'"
        shares = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        results["shares"] = shares.stdout if shares.returncode == 0 else shares.stderr
    except Exception as e:
        results["shares"] = f"Error: {e}"

    # Enumerate domains
    try:
        cmd = f"rpcclient -U '' -N {host} -p {port} -c 'enumdomains'"
        domains = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        results["domains"] = domains.stdout if domains.returncode == 0 else domains.stderr
    except Exception as e:
        results["domains"] = f"Error: {e}"

    # Enumerate groups
    try:
        cmd = f"rpcclient -U '' -N {host} -p {port} -c 'enumdomgroups'"
        groups = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        results["groups"] = groups.stdout if groups.returncode == 0 else groups.stderr
    except Exception as e:
        results["groups"] = f"Error: {e}"

    # Null session bind and basic info
    try:
        cmd = f"rpcclient -U '' -N {host} -p {port} -c 'srvinfo'"
        srvinfo = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        results["srvinfo"] = srvinfo.stdout if srvinfo.returncode == 0 else srvinfo.stderr
    except Exception as e:
        results["srvinfo"] = f"Error: {e}"

    return results