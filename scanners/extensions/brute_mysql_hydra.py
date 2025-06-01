from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def brute_mysql_hydra(self, plugin_results=None):
    """
    Attempt SMB brute-force using hydra.
    Uses user and password wordlists from options or defaults.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Get wordlists from options or use defaults
    userlist = self.options.get("mysql_userlist", "/usr/share/wordlists/user.txt")
    passlist = self.options.get("mysql_passlist", "/usr/share/wordlists/rockyou.txt")

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
        output_path = tmp_file.name

    # Handle threads later...
    cmd = (
        f"hydra -L {userlist} -P {passlist} -o {output_path} -t 32 -f -s {port} {host} smb"
    )
    logging.info(f"[brute_mysql] Executing: {cmd}")

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
        results = []
        with open(output_path, "r") as f:
            for line in f:
                if ":ssh:" in line and "login:" in line:
                    results.append(line.strip())

        return {"cmd": cmd, "results": results}

    except Exception as e:
        logging.error(f"[brute_mysql] Error during hydra brute-force: {e}")
        return {"cmd": cmd, "error": str(e)}

brute_mysql_hydra.depends_on = ["scan_tcp_scanner"]