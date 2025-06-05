from core.imports import *
from scanners.scanner import Scanner

@Scanner.register_args
def brute_smtp_userenum_args(parser, get_protocol_group):
    brute_group = get_protocol_group(parser, "bruteforce")
    brute_group.add_argument("--smtp-userlist", nargs="+", help="User wordlist(s) for SMTP user enumeration (patator)")

@Scanner.extend
def brute_smtp_userenum(self, plugin_results=None):
    """
    Attempt SMTP user enumeration using patator.
    Uses one or more user wordlists from options or defaults.
    Returns:
        dict: { "cmd": [...], "results": {...}, "all_found": [...] }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Accept multiple userlists, prepend general lists if present
    userlists = self.options.get("smtp_userlist") or ["/usr/share/wordlists/user.txt"]
    general_userlists = self.options.get("general_userlist") or []

    if isinstance(userlists, str):
        userlists = [userlists]
    if isinstance(general_userlists, str):
        general_userlists = [general_userlists]
    # Ensure general lists are sorted to the top
    userlists = sorted(set(general_userlists), key=lambda x: general_userlists.index(x)) + [u for u in userlists if u not in general_userlists]

    cmds = []
    results = {}
    all_found = []

    for userlist in userlists:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
            output_path = tmp_file.name

        cmd = (
            f"patator smtp_user_enum host={host} port={port} user=FILE0 0={userlist} "
            f"-x ignore:code=550 -o {output_path}"
        )
        cmds.append(cmd)
        logging.info(f"[brute_smtp_userenum] Executing: {cmd}")

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
            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        # Patator marks valid users with "status=success" or similar
                        if "status=success" in line or "User found" in line:
                            found.append(line.strip())
            else:
                logging.warning(f"[brute_smtp_userenum] Output file not found: {output_path}")

            results[userlist] = {
                "output_path": output_path,
                "found": found
            }
            all_found.extend(found)

        except Exception as e:
            logging.error(f"[brute_smtp_userenum] Error during patator SMTP user enum: {e}")
            results[userlist] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found}

brute_smtp_userenum.depends_on = ["scan_tcp_scanner"]
