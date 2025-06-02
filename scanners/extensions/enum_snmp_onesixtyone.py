from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_snmp_onesixtyone(self, plugin_results=None):
    """
    Run onesixtyone SNMP scanner against the current host/port using one or more community string wordlists.
    Accepts multiple wordlists (snmp_userlist and general_userlist).
    Returns:
        dict: { "cmd": [...], "results": {...}, "all_found": [...] }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Check if the service name contains 'snmp'
    service = port_obj.get("service", {}) if port_obj else {}
    service_name = service.get("name", "").lower()
    if "snmp" not in service_name:
        logging.warning(f"[enum_snmp_onesixtyone] Skipping port {port}: service is not SNMP ({service_name})")
        return {"skipped": f"Service is not SNMP: {service_name}", "report_fields": ["all_found", "error"]}

    # Accept multiple wordlists, prepend general_userlist if present
    userlists = self.options.get("snmp_communitylist") or [
        os.path.join(
            os.environ.get("SECLISTS", "/usr/share/seclists"),
            "Discovery", "SNMP", "snmp.txt"
        )
    ]
    general_userlists = self.options.get("general_userlist") or []
    if isinstance(userlists, str):
        userlists = [userlists]
    if isinstance(general_userlists, str):
        general_userlists = [general_userlists]
    userlists = sorted(set(general_userlists), key=lambda x: general_userlists.index(x)) + [u for u in userlists if u not in general_userlists]

    cmds = []
    results = {}
    all_found = []

    for userlist in userlists:
        if not os.path.exists(userlist):
            logging.warning(f"[enum_snmp_onesixtyone] Wordlist not found: {userlist}")
            results[userlist] = {"error": f"Wordlist not found: {userlist}"}
            continue

        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
            output_path = tmp_file.name

        cmd = f"onesixtyone -c {userlist} -o {output_path} {host}"
        cmds.append(cmd)
        logging.info(f"[enum_snmp_onesixtyone] Executing: {cmd}")

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

            # Parse onesixtyone output (simple text parsing)
            found = []
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        found.append(line)
            results[userlist] = {
                "output_path": output_path,
                "found": found
            }
            all_found.extend(found)

        except Exception as e:
            logging.error(f"[enum_snmp_onesixtyone] Error during onesixtyone scan: {e}")
            results[userlist] = {"error": str(e)}

    return {"cmd": cmds, "results": results, "all_found": all_found, "report_fields": ["all_found", "error"]}

enum_snmp_onesixtyone.depends_on = ["scan_udp_scanner"]