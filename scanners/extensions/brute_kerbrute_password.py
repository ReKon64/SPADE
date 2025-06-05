from core.imports import *
from scanners.scanner import Scanner

@Scanner.register_args
def brute_ftp_hydra_args(parser, get_protocol_group):
    brute_group = get_protocol_group(parser, "bruteforce")
    brute_group.add_argument("--kerbrute-userlist", nargs="+", help="User wordlist(s) for kerberos bruteforce (kerbrute)")
    brute_group.add_argument("--kerbrute-passlist", nargs="+", help="Password wordlist(s) for kerberos bruteforce (kerbrute)")

@Scanner.extend
def brute_kerbrute_password(self, plugin_results=None):
    """
    Brute-force Kerberos passwords using kerbrute, leveraging usernames found by brute_kerbrute_userenum.
    Returns:
        dict: { "cmd": ..., "results": ..., "all_found": ... }
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
        for key in [
            "domain", "DNS_Domain_Name", "DNS_Tree_Name", "NetBIOS_Domain_Name"
        ]:
            value = host_json.get(key)
            if value and value != "unknown":
                domain = value
                break
        if not domain and "ldap_info" in host_json and isinstance(host_json["ldap_info"], dict):
            for value in host_json["ldap_info"].values():
                if value and value != "unknown":
                    domain = value.strip().rstrip(".")
                    break
    if not domain:
        logging.warning("[brute_kerbrute_password] No domain found via options or host info. Skipping.")
        return {"skipped": "No domain found via options or host info."}
    dc_ip = self.options.get("kerbrute_dc", host)

    # Get usernames from brute_kerbrute_userenum results
    userenum_result = plugin_results.get("brute_kerbrute_userenum", {})
    usernames = []
    if userenum_result and "all_found" in userenum_result:
        usernames = userenum_result["all_found"]
    if not usernames:
        logging.warning("[brute_kerbrute_password] No usernames found from userenum, skipping brute-force.")
        return {"skipped": "No usernames found from userenum."}

    # Accept multiple passlists, prepend general lists if present
    passlists = self.options.get("kerbrute_passlist") or ["/usr/share/wordlists/rockyou.txt"]
    general_passlists = self.options.get("general_passlist") or []
    if isinstance(passlists, str):
        passlists = [passlists]
    if isinstance(general_passlists, str):
        general_passlists = [general_passlists]
    passlists = sorted(set(general_passlists), key=lambda x: general_passlists.index(x)) + [p for p in passlists if p not in general_passlists]

    threads = self.options.get("kerbrute_threads", 64)
    output_file_base = self.options.get("kerbrute_password_output", "valid_ad_passwords")

    cmds = []
    results = {}
    all_found = []

    # Write usernames to a temp file for kerbrute
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as userfile:
        for user in usernames:
            userfile.write(user + "\n")
        userfile_path = userfile.name

    for idx, passlist in enumerate(passlists):
        output_file = f"{output_file_base}_{idx}" if len(passlists) > 1 else output_file_base
        cmd = (
            f"kerbrute passwordspray -v -d {domain} --dc {dc_ip} {userfile_path} {passlist} -t {threads} -o {output_file}"
        )
        cmds.append(cmd)
        logging.info(f"[brute_kerbrute_password] Executing: {cmd}")

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
                logging.warning(f"[brute_kerbrute_password] Output file not found: {output_file}")

            results[passlist] = {
                "output_path": output_file,
                "found": found
            }
            all_found.extend(found)

        except Exception as e:
            logging.error(f"[brute_kerbrute_password] Error during kerbrute password spray: {e}")
            results[passlist] = {"error": str(e)}

    # Clean up temp user file
    try:
        os.remove(userfile_path)
    except Exception:
        pass

    return {"cmd": cmds, "results": results, "all_found": all_found, "domain": domain, "dc_ip": dc_ip}

brute_kerbrute_password.depends_on = ["scan_tcp_scanner", "enum_ldap_get_user_desc", "brute_kerbrute_userenum"]