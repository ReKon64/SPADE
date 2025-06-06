from core.imports import *
from scanners.scanner import Scanner
from core.arg_registry import add_argument_once

@Scanner.register_args
def brute_winrm_patator_args(parser, get_protocol_group):
    brute_group = get_protocol_group(parser, "bruteforce")
    add_argument_once(brute_group, "--winrm-userlist", nargs="+", help="User wordlist(s) for WinRM bruteforce (patator)")
    add_argument_once(brute_group, "--winrm-passlist", nargs="+", help="Password wordlist(s) for WinRM bruteforce (patator)")

@Scanner.extend
def brute_winrm_patator(self, plugin_results=None):
    """
    Attempt WinRM brute-force using patator.
    Uses one or more user and password wordlists from options or defaults.
    Returns:
        dict: { "cmd": [...], "results": {...}, "all_found": [...] }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Accept multiple userlists and passlists, prepend general lists if present
    userlists = self.options.get("winrm_userlist") or ["/usr/share/wordlists/user.txt"]
    passlists = self.options.get("winrm_passlist") or ["/usr/share/wordlists/rockyou.txt"]

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

    cmds = []
    results = {}
    all_found = []

    for userlist in userlists:
        for passlist in passlists:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
                output_path = tmp_file.name

            cmd = (
                f"patator winrm_login host={host} port={port} "
                f"user=FILE0 password=FILE1 0={userlist} 1={passlist} "
                f"-x ignore:code=401 "
                f"-o {output_path}"
            )
            cmds.append(cmd)
            logging.info(f"[brute_winrm] Executing: {cmd}")

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
                with open(output_path, "r") as f:
                    for line in f:
                        if "status=success" in line or "login succeeded" in line.lower():
                            found.append(line.strip())
                results[f"{userlist}|{passlist}"] = {
                    "output_path": output_path,
                    "found": found
                }
                all_found.extend(found)

            except Exception as e:
                logging.error(f"[brute_winrm] Error during patator brute-force: {e}")
                results[f"{userlist}|{passlist}"] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found}

brute_winrm_patator.depends_on = ["scan_tcp_scanner"]