from core.imports import *
from scanners.scanner import Scanner
import re

@Scanner.extend
def enum_ldap_get_user_desc(self):
    """
    Enumerate LDAP user descriptions using ldapsearch.
    Uses rdp-ntlm-info:DNS_Tree_Name or host-level ldap_info as the domain if available.
    Returns:
        dict: { "command": ..., "results": ... }
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    # Try to get the domain from host_json['ldap_info'] or rdp-ntlm-info
    port_obj = self.options["current_port"].get("port_obj", {})
    host_json = self.options["current_port"].get("host_json", {})
    domain = None

    # Prefer rdp-ntlm-info:DNS_Tree_Name if available in port's scripts
    # findings = port_obj.get("scripts", {}) if port_obj else {}
    # rdp_ntlm = findings.get("rdp-ntlm-info", {})
    # if isinstance(rdp_ntlm, dict):
    #     domain = rdp_ntlm.get("DNS_Tree_Name")

    # Fallback to host-level DNS_Tree_Name, DNS_Domain_Name, or ldap_info
    # This might be bad code
    # if not domain:
    #     for key in ("DNS_Tree_Name", "DNS_Domain_Name"):
    #         if key in host_json and host_json[key]:
    #             domain = host_json[key].strip().rstrip(".")
    #             break

    if not domain and "ldap_info" in host_json and isinstance(host_json["ldap_info"], dict):
        logging.debug(f"[LDAP_USER_DESC] Will use {domain}")
        for value in host_json["ldap_info"].values():
            domain = value.strip().rstrip(".")
            
            break

    if not domain:
        logging.error(f"[LDAP_USER_DESC] Domain name not found in rdp-ntlm-info or ldap_info.")
        results["error"] = "Domain name not found in rdp-ntlm-info or ldap_info."
        return {"command": None, "results": results}

    # Extract dn parts
    dn_parts = [f"dc={part}" for part in domain.split(".") if part]
    base_dn = ",".join(dn_parts)
    logging.debug(f"[LDAP_USER_DESC] base_dn {base_dn}")
    cmd = (
        f'ldapsearch -x -H ldap://{host} -LLL -b "{base_dn}" '
        f'"(sAMAccountName=*)" sAMAccountName description | '
        "awk 'BEGIN{RS=\"\";FS=\"\\n\"}{user=\"\";desc=\"[no description]\";for(i=1;i<=NF;i++){if($i~/^sAMAccountName:/){user=substr($i,index($i,\":\")+2)}else if($i~/^description:/){desc=substr($i,index($i,\":\")+2);for(j=i+1;j<=NF&&$j~/^ /;j++){desc=desc\" \"substr($j,2);i=j}}}if(user!=\"\"){print user\": \"desc\"\\n\"}}'"
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

    return {"command": cmd, "results": results}