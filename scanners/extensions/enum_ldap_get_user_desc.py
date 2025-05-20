from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_ldap_get_user_desc(self):
    """
    Enumerate LDAP user descriptions using nxc.
    Runs: nxc ldap -u ' ' -p ' ' -M get-user-desc
    Returns:
        dict: Results of the nxc LDAP get-user-desc command
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    try:
        cmd = f"nxc ldap -u '' -p '' -M get-user-desc {host} -P {port}"
        logging.info(f"Executing: {cmd}")
        output = subprocess.run(
            cmd,
            shell=True,
            capture_output=not verbosity,
            text=True,
            timeout=30
        )
        if verbosity:
            from core.logging import run_and_log
            output_text = run_and_log(cmd, very_verbose=True)
        else:
            output_text = output.stdout if output.returncode == 0 else output.stderr

        results["output"] = output_text
        results["returncode"] = output.returncode if not verbosity else 0
    except Exception as e:
        results["error"] = str(e)

    return results