from scanners.scanner import Scanner
from core.arg_registry import add_argument_once

@Scanner.register_args
def built_in_args(parser, get_protocol_group):
    # Brute group
    brute_group = get_protocol_group(parser, "bruteforce")
    add_argument_once(brute_group, "--general-userlist", nargs="+", help="General user wordlist(s) for all brute modules")
    add_argument_once(brute_group, "--general-passlist", nargs="+", help="General password wordlist(s) for all brute modules")
    add_argument_once(brute_group, "--enable-bruteforce", action="store_true", help="Enable brute force plugins")

    # Target group
    target_group = get_protocol_group(parser, "target")
    add_argument_once(target_group, "-t", "--target", help="One or more IP / Domain")
    add_argument_once(target_group, "-x", "--xml-input", help="Path to existing Nmap XML file to use as input (skips scanning and uses this for enumeration)")

    # Domain group
    domain_group = get_protocol_group(parser, "domain")
    add_argument_once(domain_group, "-d", "--domain", help="Domain name to use for Kerberos and LDAP operations")

    # Nmap/Scan group
    nmap_group = get_protocol_group(parser, "nmap")
    add_argument_once(nmap_group, "-tp", "--tcp-ports", default="-p-", help="Ports to scan. Passed directly to nmap. Default -p-")
    add_argument_once(nmap_group, "-up", "--udp-ports", default="--top-ports=100", help="WIP")
    add_argument_once(nmap_group, "-at", "--tcp-options", help="Additional flags to inject into the TCP nmap command")
    add_argument_once(nmap_group, "-au", "--udp-options", help="Additional flags to inject into the UDP nmap command")
    add_argument_once(nmap_group, "-T", "--threads", default=16, help="Number of threads scanner will use. I suggest 64")

    # Logging group
    logging_group = get_protocol_group(parser, "logging")
    add_argument_once(logging_group, "-v", "--verbose", action="store_true", help="Enable verbose output")
    add_argument_once(logging_group, "-rt", "--realtime", action="store_true", help="Enable real time STDOUT for modules")
    add_argument_once(logging_group, "-m", "--memory", action="store_true", help="Add memory usage to logging")
    add_argument_once(logging_group, "-o", "--output", help="Output directory for reports and payloads. Defaults to CWD")
    add_argument_once(logging_group, "--report", nargs="?", const=True, default=False, help="Generate HTML report. Supply with a filepath to a jinja2 template to use custom report.")