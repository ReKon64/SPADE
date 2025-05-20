from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_smb_get_shares(self):
    """
    Enumerate SMB shares using nxc.
    Runs: nxc smb <host> -u ' ' -p ' ' --shares
    Returns:
        dict: Results of the nxc SMB shares command
    """
    host = self.options["current_port"]["host"]
    verbosity = self.options.get("realtime", False)
    results = {}

    try:
        cmd = f"nxc smb {host} -u '' -p '' --shares"
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