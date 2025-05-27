from core.imports import *
from scanners.scanner import Scanner

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

    # Try to fetch domain and DC IP from host_json or fallback to options/host
    domain = None
    dc_ip = host

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

    # If still not found, fallback to options or default
    if not domain:
        domain = self.options.get("kerbrute_domain", "INLANEFREIGHT.LOCAL")
    dc_ip = self.options.get("kerbrute_dc", host)

    userlist = self.options.get(
        "kerbrute_userlist",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
    )
    threads = self.options.get("kerbrute_threads", 64)
    output_file = self.options.get("kerbrute_output", "valid_ad_users")

    cmd = (
        f"kerbrute userenum -v -d {domain} --dc {dc_ip} {userlist} -t {threads} -o {output_file}"
    )
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

        # Parse output file for valid usernames
        results = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append(line)
        else:
            logging.warning(f"[brute_kerbrute_userenum] Output file not found: {output_file}")

        return {"cmd": cmd, "results": results, "domain": domain, "dc_ip": dc_ip}

    except Exception as e:
        logging.error(f"[brute_kerbrute_userenum] Error during kerbrute userenum: {e}")
        return {"cmd": cmd, "error": str(e), "domain": domain, "dc_ip": dc_ip}
    
brute_kerbrute_userenum.depends_on = ["scan_tcp_scanner", "enum_ldap_get_user_desc"]