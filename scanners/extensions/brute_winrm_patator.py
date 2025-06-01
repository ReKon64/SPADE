from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def brute_winrm_patator(self, plugin_results=None):
    """
    Attempt WinRM brute-force using patator.
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
    userlist = self.options.get("patator_userlist", "/usr/share/wordlists/user.txt")
    passlist = self.options.get("patator_passlist", "/usr/share/wordlists/rockyou.txt")

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
        output_path = tmp_file.name

    cmd = (
        f"patator winrm_login host={host} port={port} "
        f"user=FILE0 password=FILE1 0={userlist} 1={passlist} "
        f"-x ignore:code=401 "
        f"-o {output_path}"
    )
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

        # Parse patator output for successful logins
        results = []
        with open(output_path, "r") as f:
            for line in f:
                # Patator marks successful attempts with 'status=success' or similar
                if "status=success" in line or "login succeeded" in line.lower():
                    results.append(line.strip())

        return {"cmd": cmd, "results": results}

    except Exception as e:
        logging.error(f"[brute_winrm] Error during patator brute-force: {e}")
        return {"cmd": cmd, "error": str(e)}

brute_winrm_patator.depends_on = ["scan_tcp_scanner"]