from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_snmp_onesixtyone(self, plugin_results=None):
    """
    Run onesixtyone SNMP scanner against the current host/port using common community strings.
    Runs if the port's service name contains 'snmp'.
    Supports real-time logging if enabled.
    Returns:
        dict: { "cmd": ..., "results": ... }
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
        return {"skipped": f"Service is not SNMP: {service_name}"}

    # Path to common SNMP community strings (adjust if needed)
    seclists_path = os.path.join(
        os.environ.get("SECLISTS", "/usr/share/seclists"),
        "Discovery", "SNMP", "snmp.txt"
    )
    if not os.path.exists(seclists_path):
        logging.warning(f"[enum_snmp_onesixtyone] Wordlist not found: {seclists_path}")
        return {"error": f"Wordlist not found: {seclists_path}"}

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
        output_path = tmp_file.name

    cmd = f"onesixtyone -c {seclists_path} -o {output_path} {host}"

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
        with open(output_path, "r") as f:
            lines = f.readlines()
        results = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                results.append(line)

        return {"cmd": cmd, "results": results}

    except Exception as e:
        logging.error(f"[enum_snmp_onesixtyone] Error during onesixtyone scan: {e}")
        return {"cmd": cmd, "error": str(e)}

enum_snmp_onesixtyone.depends_on = ["scan_udp_scanner"]