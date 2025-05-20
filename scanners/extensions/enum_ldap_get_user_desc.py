from core.imports import *
from scanners.scanner import Scanner
import re

@Scanner.extend
def enum_ldap_get_user_desc(self):
    """
    Enumerate LDAP user descriptions using ldapsearch.
    Uses rdp-ntlm-info:DNS_Tree_Name as the domain if available.
    Runs: ldapsearch -x -H ldap://{host} -LLL -b "dc=<dn1>,dc=<dn2>" "(sAMAccountName=*)" sAMAccountName description | awk ...
    Returns:
        dict: Results of the ldapsearch user description command
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    # Attempt to fetch the domain name from rdp-ntlm-info:DNS_Tree_Name first
    domain = None
    port_obj = self.options["current_port"].get("port_obj", {})
    findings = port_obj.get("scripts", {}) if port_obj else {}

    # Prefer rdp-ntlm-info:DNS_Tree_Name if available
    rdp_ntlm = findings.get("rdp-ntlm-info", {})
    if isinstance(rdp_ntlm, dict):
        domain = rdp_ntlm.get("DNS_Tree_Name")

    # Fallback to other common keys if not found
    if not domain:
        for key in ["DNS_Domain_Name", "dns_domain", "domain"]:
            domain = findings.get(key) or self.options.get(key)
            logging.debug(f"[DIG] Domain : {domain}")
            if domain:
                break

    if not domain:
        results["error"] = "Domain name not found in rdp-ntlm-info or findings/options."
        return results

    # Extract dn parts
    dn_parts = [f"dc={part}" for part in domain.split(".") if part]
    base_dn = ",".join(dn_parts)
    logging.debug(f"[DIG] base_dn {base_dn}")
    cmd = (
        f'ldapsearch -x -H ldap://{host} -LLL -b "{base_dn}" '
        f'"(sAMAccountName=*)" sAMAccountName description | '
        "awk 'BEGIN{ORS=\"\";} /^sAMAccountName:/ {user=$0} /^description:/ {print user \"\\n\" $0 \"\\n\\n\"}'"
    )

    try:
        logging.info(f"Executing: {cmd}")
        if verbosity:
            from core.logging import run_and_log
            output_text = run_and_log(cmd, very_verbose=True)
            results["returncode"] = 0
        else:
            output = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output_text = output.stdout if output.returncode == 0 else output.stderr
            results["returncode"] = output.returncode

        results["output"] = output_text
        results["domain"] = domain
        results["base_dn"] = base_dn
    except Exception as e:
        results["error"] = str(e)

    return results