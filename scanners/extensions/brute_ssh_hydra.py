from core.imports import *
from scanners.scanner import Scanner

@Scanner.register_args
def brute_ssh_hydra_args(parser, get_protocol_group):
    brute_group = get_protocol_group(parser, "bruteforce")
    brute_group.add_argument("--ssh-userlist", nargs="+", help="User wordlist(s) for SSH bruteforce (hydra)")
    brute_group.add_argument("--ssh-passlist", nargs="+", help="Password wordlist(s) for SSH bruteforce (hydra)")

@Scanner.extend
def brute_ssh_hydra(self, plugin_results=None):
    """
    Attempt SSH brute-force using hydra.
    Uses one or more user and password wordlists from options or defaults.
    Returns:
        dict: { "cmd": [...], "results": {...} }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Accept multiple userlists and passlists
    userlists = self.options.get("ssh_userlist") or ["/usr/share/wordlists/user.txt"]
    passlists = self.options.get("ssh_passlist") or ["/usr/share/wordlists/rockyou.txt"]

    # If single string, wrap in list
    if isinstance(userlists, str):
        userlists = [userlists]
    if isinstance(passlists, str):
        passlists = [passlists]

    cmds = []
    results = {}
    all_found = []

    for userlist in userlists:
        for passlist in passlists:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
                output_path = tmp_file.name

            cmd = (
                f"hydra -L {userlist} -P {passlist} -o {output_path} -t 4 -f -s {port} {host} ssh"
            )
            cmds.append(cmd)
            logging.info(f"[brute_ssh] Executing: {cmd}")

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

                # Parse hydra output for successful logins
                found = []
                with open(output_path, "r") as f:
                    for line in f:
                        if ":ssh:" in line and "login:" in line:
                            found.append(line.strip())
                results[f"{userlist}|{passlist}"] = {
                    "output_path": output_path,
                    "found": found
                }
                all_found.extend(found)

            except Exception as e:
                logging.error(f"[brute_ssh] Error during hydra brute-force: {e}")
                results[f"{userlist}|{passlist}"] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found}