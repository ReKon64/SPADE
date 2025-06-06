from core.imports import *
from scanners.scanner import Scanner
from core.arg_registry import add_argument_once

@Scanner.register_args
def brute_kerbrute_userenum_args(parser, get_protocol_group):
    brute_group = get_protocol_group(parser, "bruteforce")
    add_argument_once(brute_group, "--kerbrute-userlist", nargs="+", help="User wordlist(s) for kerberos bruteforce (kerbrute)")
    
@Scanner.extend
def brute_kerbrute_userenum(self, plugin_results=None):
    """
    Enumerate valid Active Directory usernames using kerbrute.
    Attempts to fetch domain details from host-level info, including LDAP info.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    host_json = self.options["current_port"].get("host_json", {})

    # Domain override via argparse/option
    domain = self.options.get("domain")
    dc_ip = host

    if not domain:
        # Try common keys for domain
        for key in [
            "domain", "DNS_Domain_Name", "DNS_Tree_Name", "NetBIOS_Domain_Name"
        ]:
            value = host_json.get(key)
            logging.debug(f"[KEBRUTE_USERENUM] Domain Key used: {value}")
            if value and value != "unknown":
                domain = value
                break

        # Fallback to LDAP info if not found
        if not domain and "ldap_info" in host_json and isinstance(host_json["ldap_info"], dict):
            for value in host_json["ldap_info"].values():
                if value and value != "unknown":
                    domain = value.strip().rstrip(".")
                    logging.debug(f"[KEBRUTE_USERENUM] Falling back to LDAP info: {value}")
                    break

    # If still not found, fallback to options (not to a hardcoded default)
    if not domain:
        logging.warning("[brute_kerbrute_userenum] No domain found via options or host info. Skipping.")
        return {"skipped": "No domain found via options or host info."}
    dc_ip = self.options.get("kerbrute_dc", host)

    # Accept multiple userlists
    userlists = self.options.get(
        "kerbrute_userlist",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
    )
    if isinstance(userlists, str):
        userlists = [userlists]

    general_userlists = self.options.get("general_userlist") or []
    if isinstance(general_userlists, str):
        general_userlists = [general_userlists]
    # Ensure general lists are sorted to the top
    userlists = sorted(set(general_userlists), key=lambda x: general_userlists.index(x)) + [u for u in userlists if u not in general_userlists]

    threads = self.options.get("kerbrute_threads", 64)
    output_file_base = self.options.get("kerbrute_output", "valid_ad_users")

    cmds = []
    results = {}
    all_found = []

    for idx, userlist in enumerate(userlists):
        output_file = f"{output_file_base}_{idx}" if len(userlists) > 1 else output_file_base
        cmd = (
            f"kerbrute userenum -v -d {domain} --dc {dc_ip} {userlist} -t {threads} -o {output_file}"
        )
        cmds.append(cmd)
        logging.info(f"[brute_kerbrute_userenum] Executing: {cmd}")

        try:
            if self.options.get("realtime", False):
                from core.logging import run_and_log
                run_and_log(cmd, very_verbose=True)
            else:
                subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=True
                )

            found = []
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            found.append(line)
            else:
                logging.warning(f"[brute_kerbrute_userenum] Output file not found: {output_file}")

            results[userlist] = {
                "output_path": output_file,
                "found": found
            }
            all_found.extend(found)

        except Exception as e:
            logging.error(f"[brute_kerbrute_userenum] Error during kerbrute userenum: {e}")
            results[userlist] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found, "domain": domain, "dc_ip": dc_ip}
    
brute_kerbrute_userenum.depends_on = ["scan_tcp_scanner", "enum_ldap_get_user_desc"]