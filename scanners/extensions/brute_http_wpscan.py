from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def brute_http_wpscan(self, plugin_results=None):
    """
    Attempt WordPress brute-force using wpscan.
    Prefers XML-RPC if available, otherwise falls back to regular login.
    Uses one or more user and password wordlists from options or defaults.
    Returns:
        dict: { "cmd": [...], "results": {...}, "all_found": [...] }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    url = f"{protocol}://{host}:{port}/"
    verbosity = self.options.get("realtime", False)

    # Accept multiple userlists and passlists, prepend general lists if present
    userlists = self.options.get("wp_userlist") or ["/usr/share/wordlists/user.txt"]
    passlists = self.options.get("wp_passlist") or ["/usr/share/wordlists/rockyou.txt"]
    general_userlists = self.options.get("general_userlist") or []
    general_passlists = self.options.get("general_passlist") or []

    if isinstance(userlists, str):
        userlists = [userlists]
    if isinstance(passlists, str):
        passlists = [passlists]
    if isinstance(general_userlists, str):
        general_userlists = [general_userlists]
    if isinstance(general_passlists, str):
        general_passlists = [general_passlists]

    # Ensure general lists are sorted to the top
    userlists = sorted(set(general_userlists), key=lambda x: general_userlists.index(x)) + [u for u in userlists if u not in general_userlists]
    passlists = sorted(set(general_passlists), key=lambda x: general_passlists.index(x)) + [p for p in passlists if p not in general_passlists]

    # Determine if XML-RPC is available from enum_http_wpscan results
    xmlrpc_available = False
    wpscan_result = plugin_results.get("enum_http_wpscan", {})
    if isinstance(wpscan_result, dict):
        scan_data = wpscan_result.get("results", {})
        if isinstance(scan_data, dict):
            xmlrpc_available = scan_data.get("xmlrpc_enabled", False)

    cmds = []
    results = {}
    all_found = []

    for userlist in userlists:
        for passlist in passlists:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wpscan') as tmp_file:
                output_path = tmp_file.name

            if xmlrpc_available:
                # Prefer XML-RPC
                cmd = (
                    f"wpscan --url {url} --enumerate u --passwords {passlist} --usernames {userlist} "
                    f"--brute-force-method xmlrpc --output {output_path} --format json"
                )
            else:
                # Fallback to regular login
                cmd = (
                    f"wpscan --url {url} --enumerate u --passwords {passlist} --usernames {userlist} "
                    f"--brute-force-method wp-login --output {output_path} --format json"
                )
            cmds.append(cmd)
            logging.info(f"[brute_http_wpscan] Executing: {cmd}")

            try:
                if verbosity:
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
                # Parse wpscan JSON output for successful logins
                if os.path.exists(output_path):
                    with open(output_path, "r") as f:
                        try:
                            data = json.load(f)
                            creds = data.get("brute_force", {}).get("valid_credentials", [])
                            for cred in creds:
                                user = cred.get("login")
                                pwd = cred.get("password")
                                if user and pwd:
                                    found.append(f"{user}:{pwd}")
                        except Exception as e:
                            logging.warning(f"[brute_http_wpscan] Failed to parse JSON: {e}")
                results[f"{userlist}|{passlist}"] = {
                    "output_path": output_path,
                    "found": found
                }
                all_found.extend(found)

            except Exception as e:
                logging.error(f"[brute_http_wpscan] Error during wpscan brute-force: {e}")
                results[f"{userlist}|{passlist}"] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found}

brute_http_wpscan.depends_on = ["scan_tcp_scanner", "enum_http_curl_confirmation", "enum_http_wpscan"]
