from core.imports import *
from scanners.scanner import Scanner

@Scanner.register_args
def enum_snmp_snmpwalk_args(parser, get_protocol_group):
    pass  # No specific arguments for enum_snmp_snmpwalk yet

@Scanner.extend
def enum_snmp_snmpwalk(self, plugin_results=None):
    """
    Run snmpwalk against the current host using discovered SNMP community strings.
    Uses results from enum_snmp_onesixtyone.
    Returns:
        dict: { "cmds": [...], "results": {...} }
    """
    if plugin_results is None:
        plugin_results = {}

    # Get host and port info
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

    # Get community strings from onesixtyone results
    onesixtyone_result = plugin_results.get("enum_snmp_onesixtyone", {})
    community_lines = onesixtyone_result.get("results", [])
    community_strings = set()
    for line in community_lines:
        match = re.search(r"\[(.*?)\]", line)
        if match:
            community_strings.add(match.group(1))

    if not community_strings:
        return {"skipped": "No SNMP community strings found by onesixtyone"}

    results = {}
    cmds = []
    logging.info(f"[SNMP_WALK] Starting against: {host}:{port} v{version}")
    for community in community_strings:
        # Try both v1 and v2c
        for version in ["1", "2c"]:
            cmd = f"snmpwalk -v {version} -c {community} -On -r 1 -t 2 -p {port} {host} NET-SNMP-EXTEND-MIB::nsExtendOutputFull"
            logging.debug(f"[SNMP_WALK] Executing: {cmd}")
            cmds.append(cmd)
            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = proc.stdout.strip()
                if output:
                    results[f"{community}/v{version}"] = output
            except Exception as e:
                results[f"{community}/v{version}"] = f"Error: {e}"

    return {"cmds": cmds, "results": results}

enum_snmp_snmpwalk.depends_on = ["scan_udp_scanner","enum_snmp_onesixtyone"]