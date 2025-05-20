from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_smb_get_shares(self):
    """
    List SMB shares using smbclient.
    Runs: smbclient -N -L \\host -p port
    Returns:
        dict: Results of the smbclient shares command
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    try:
        cmd = f"smbclient -N -L \\\\{host} -p {port}"
        logging.info(f"Executing: {cmd}")
        if verbosity:
            from core.logging import run_and_log
            output_text = run_and_log(cmd, very_verbose=True)
            results["output"] = output_text
            results["returncode"] = 0
        else:
            output = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            results["output"] = output.stdout if output.returncode == 0 else output.stderr
            results["returncode"] = output.returncode
    except Exception as e:
        results["error"] = str(e)

    return results