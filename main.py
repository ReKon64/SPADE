# SPADE - Scalable Plug-and-play Auto Detection Engine

# Import components
from core.imports import *
from scanners.scanner import Scanner
from core.logging import SafeFormatter
from core.reporter import Reporter
from core.plugin_monitor import plugin_monitor
from core.signal_handler import handler as exit_handler

def main():
    parser = argparse.ArgumentParser(description="SPADE - Scalable Plug-and-play Auto Detection Engine")

    # Target Acquisition options group
    target_group = parser.add_argument_group("Target Acquisition Options", "Options for acquiring targets")
    target_group.add_argument("-t", "--target", help="One or more IP / Domain")
    target_group.add_argument("-x", "--xml-input", help="Path to existing Nmap XML file to use as input (skips scanning and uses this for enumeration)")

    # Domain options group
    domain_group = parser.add_argument_group("Domain Options", "Options for domain-related operations")
    domain_group.add_argument("-d", "--domain", help="Domain name to use for Kerberos and LDAP operations")

    # Nmap/Scan options group
    nmap_group = parser.add_argument_group("Nmap/Scan options", "Options for port scanning and threading")
    nmap_group.add_argument("-tp", "--tcp-ports", default="-p-", help="Ports to scan. Passed directly to nmap. Default -p-")
    nmap_group.add_argument("-up", "--udp-ports", default="--top-ports=100", help="WIP")
    nmap_group.add_argument('-at', "--tcp-options", help="Additional flags to inject into the TCP nmap command")
    nmap_group.add_argument('-au', "--udp-options", help="Additional flags to inject into the UDP nmap command")
    nmap_group.add_argument("-T", "--threads", default=16, help="Number of threads scanner will use. I suggest 64")

    # Logging control and output options group
    logging_group = parser.add_argument_group("Logging and Output Options", "Options for controlling logging and output")
    logging_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    logging_group.add_argument("-rt", "--realtime", action="store_true", help="Enable real time STDOUT for modules")
    logging_group.add_argument("-m", "--memory", action="store_true", help="Add memory usage to logging")
    logging_group.add_argument("-o", "--output", help="Output directory for reports and payloads. Defaults to CWD")
    logging_group.add_argument("--report", nargs="?", const=True, default=False, help="Generate HTML report. Supply with a filepath to a jinja2 template to use custom report.")
    
    # HTTP/HTTPS options group
    http_group = parser.add_argument_group("HTTP/HTTPS Options", "Options specific to HTTP/HTTPS enumeration")
    http_group.add_argument("--ferox-wordlists", nargs="+", help="One or more wordlists to use for feroxbuster (space separated not quoted).")
    
    # API Tokens Group
    api_group = parser.add_argument_group("API Tokens", "API tokens for plugins requiring them")
    api_group.add_argument("--google-api-key", help="Google Custom Search API key for product search plugins")
    api_group.add_argument("--google-cse-id", help="Google Custom Search Engine ID for product search plugins")
    api_group.add_argument("--wpscan-api-token", help="WPScan API token for vulnerability database access")  # <-- added

    # Bruteforce Login options group
    brute_login_group = parser.add_argument_group("Bruteforce options", "Options for bruteforce login attacks")
    brute_login_group.add_argument("--enable-bruteforce", action="store_true", help="Enable bruteforce login attacks (default: off)")
    brute_login_group.add_argument("--ssh-userlist", nargs="+", help="User wordlist(s) for SSH bruteforce (hydra)")
    brute_login_group.add_argument("--ssh-passlist", nargs="+", help="Password wordlist(s) for SSH bruteforce (hydra)")
    brute_login_group.add_argument("--ftp-userlist", nargs="+", help="User wordlist(s) for FTP bruteforce (hydra)")
    brute_login_group.add_argument("--ftp-passlist", nargs="+", help="Password wordlist(s) for FTP bruteforce (hydra)")
    brute_login_group.add_argument("--smb-userlist", nargs="+", help="User wordlist(s) for SMB bruteforce (hydra)")
    brute_login_group.add_argument("--smb-passlist", nargs="+", help="Password wordlist(s) for SMB bruteforce (hydra)")
    brute_login_group.add_argument("--mysql-userlist", nargs="+", help="User wordlist(s) for MySQL bruteforce (hydra)")
    brute_login_group.add_argument("--mysql-passlist", nargs="+", help="Password wordlist(s) for MySQL bruteforce (hydra)")
    brute_login_group.add_argument("--rdp-userlist", nargs="+", help="User wordlist(s) for RDP bruteforce (patator)")
    brute_login_group.add_argument("--rdp-passlist", nargs="+", help="Password wordlist(s) for RDP bruteforce (patator)")
    brute_login_group.add_argument("--winrm-userlist", nargs="+", help="User wordlist(s) for WinRM bruteforce (patator)")
    brute_login_group.add_argument("--winrm-passlist", nargs="+", help="Password wordlist(s) for WinRM bruteforce (patator)")
    brute_login_group.add_argument("--kerbrute-userlist", nargs="+", help="User wordlist(s) for Kerberos bruteforce (kerbrute)")
    brute_login_group.add_argument("--kerbrute-passlist", nargs="+", help="Password wordlist(s) for Kerberos bruteforce (kerbrute)")
    brute_login_group.add_argument("--snmp-communitylist", nargs="+", help="Community string wordlist(s) for SNMP brute/enumeration (onesixtyone)")
    brute_login_group.add_argument("--general-userlist", nargs="+", help="General user wordlist(s) for all bruteforce plugins (space separated, not quoted)")
    brute_login_group.add_argument("--general-passlist", nargs="+", help="General password wordlist(s) for all bruteforce plugins (space separated, not quoted)")
    brute_login_group.add_argument("--smtp-userlist", nargs="+", help="User wordlist(s) for SMTP user enumeration (patator)")  # <-- added

    # Add more as needed for other protocols/tools

    args = parser.parse_args()

    # make it for all brute user/passlist args
    # Idiot-proof ferox_wordlists: split if user quoted the list
    if args.ferox_wordlists and len(args.ferox_wordlists) == 1 and " " in args.ferox_wordlists[0]:
        logging.warning(
            "[!] You provided --ferox-wordlists as a quoted string. "
            "Splitting into multiple wordlists. Next time, do NOT quote the list!"
        )
        args.ferox_wordlists = args.ferox_wordlists[0].split()
    # Idiot-proof general-userlist/passlist: split if user quoted the list
    if args.general_userlist and len(args.general_userlist) == 1 and " " in args.general_userlist[0]:
        logging.warning(
            "[!] You provided --general-userlist as a quoted string. "
            "Splitting into multiple wordlists. Next time, do NOT quote the list!"
        )
        args.general_userlist = args.general_userlist[0].split()
    if args.general_passlist and len(args.general_passlist) == 1 and " " in args.general_passlist[0]:
        logging.warning(
            "[!] You provided --general-passlist as a quoted string. "
            "Splitting into multiple wordlists. Next time, do NOT quote the list!"
        )
        args.general_passlist = args.general_passlist[0].split()
    # Idiot-proof for all brute user/passlist args: split if quoted
    for argname in [
        "ssh_userlist", "ssh_passlist", "ftp_userlist", "ftp_passlist",
        "smb_userlist", "smb_passlist", "mysql_userlist", "mysql_passlist",
        "rdp_userlist", "rdp_passlist", "winrm_userlist", "winrm_passlist",
        "kerbrute_userlist", "kerbrute_passlist", "snmp_communitylist"
    ]:
        val = getattr(args, argname, None)
        if val and len(val) == 1 and " " in val[0]:
            logging.warning(
                f"[!] You provided --{argname.replace('_', '-')} as a quoted string. "
                "Splitting into multiple wordlists. Next time, do NOT quote the list!"
            )
            setattr(args, argname, val[0].split())
    # Configure logging
    if args.memory:
        from core.logging import MemoryUsageFormatter, setup_colored_logging
        format = '%(asctime)s - %(levelname)s - [MEM: %(memory_usage)s] - %(message)s'
        if args.realtime and args.verbose:
            log_level = min(logging.DEBUG, 15)  # 10
        elif args.realtime:
            log_level = 15
        elif args.verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        
        # Create handler and formatter
        handler = logging.StreamHandler()
        formatter = MemoryUsageFormatter(format)
        handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(handler)
        
        # Add colored logging for plugin messages
        setup_colored_logging(root_logger)
    else:
        format = '%(asctime)s - %(levelname)s - %(message)s'
        if args.realtime and args.verbose:
            log_level = min(logging.DEBUG, 15)  # 10
        elif args.realtime:
            log_level = 15
        elif args.verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        logging.basicConfig(level=log_level, format=format)
        # Handler patch
        for handler in logging.getLogger().handlers:
            handler.setFormatter(SafeFormatter(format))
        
        # Add colored logging for plugin messages
        from core.logging import setup_colored_logging
        setup_colored_logging()

    # Options dictionary
    options = {
        'output_dir': args.output or os.getcwd(),
        'verbose': args.verbose,
        'realtime': args.realtime,
        'threads': args.threads,
        'target': args.target,
        'domain': args.domain,
        'tcp_ports': args.tcp_ports,
        'udp_ports': args.udp_ports,
        'tcp_options': args.tcp_options,
        'udp_options': args.udp_options,
        'ferox_wordlists': args.ferox_wordlists,
        'google_api_key': args.google_api_key,
        'google_cse_id': args.google_cse_id,
        'wpscan_api_token': args.wpscan_api_token,  # <-- added
        'enable_bruteforce': args.enable_bruteforce,
        'ssh_userlist': args.ssh_userlist,
        'ssh_passlist': args.ssh_passlist,
        'ftp_userlist': args.ftp_userlist,
        'ftp_passlist': args.ftp_passlist,
        'smb_userlist': args.smb_userlist,
        'smb_passlist': args.smb_passlist,
        'mysql_userlist': args.mysql_userlist,
        'mysql_passlist': args.mysql_passlist,
        'rdp_userlist': args.rdp_userlist,
        'rdp_passlist': args.rdp_passlist,
        'winrm_userlist': args.winrm_userlist,
        'winrm_passlist': args.winrm_passlist,
        'kerbrute_userlist': args.kerbrute_userlist,
        'kerbrute_passlist': args.kerbrute_passlist,
        'snmp_communitylist': args.snmp_communitylist,
        'general_userlist': args.general_userlist,
        'general_passlist': args.general_passlist,
        'smtp_userlist': args.smtp_userlist,  # <-- added
    }

    # Load all scanner extensions
    Scanner.load_extensions()
    scanner = Scanner(options)
    
    # Register exit handler with scanner and args
    exit_handler.register(scanner=scanner, args=args)

    # Set virtual scan plugins for all scan modes (not just XML input)
    scanner._virtual_scan_plugins = ["scan_tcp_scanner", "scan_udp_scanner"]

    # If --xml-input is provided, parse the XML and skip initial scans
    if args.xml_input:
        logging.info(f"[+] Parsing Nmap XML input file: {args.xml_input}")
        with open(args.xml_input, 'r') as f:
            xml_data = f.read()
        from scanners.nmap_parser import parse_nmap_xml
        findings = parse_nmap_xml(xml_data)
        # If both --xml-input and --target are provided, override host IPs
        if args.target:
            logging.info(f"[+] Overriding parsed host IPs with target: {args.target}")
            for host in findings.get("hosts", []):
                host["ip"] = args.target
        scanner._store_findings(findings)
        logging.info(f"[+] Parsed {len(findings.get('hosts', []))} hosts from XML input.")
    else:
        # Normal scan flow
        if not args.target:
            parser.error("the following arguments are required: -t/--target (unless --xml-input is used)")
        logging.info(f"[+] Starting initial scans against {options['target']}")
        logging.debug(f"Scanner initialized with options: {scanner.options}")

        # Run TCP and UDP scans in parallel
        scan_methods = []
        if hasattr(scanner, "scan_tcp_scan"):
            scan_methods.append("scan_tcp_scan")
        if hasattr(scanner, "scan_udp_scan"):
            scan_methods.append("scan_udp_scan")

        scan_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(scanner.scan_tcp_scan): "tcp",
                executor.submit(scanner.scan_udp_scan): "udp"
            }
            enum_futures = {}
            for future in concurrent.futures.as_completed(futures):
                proto = futures[future]
                try:
                    result = future.result()
                    # Parse and merge results
                    xml_path = None
                    if isinstance(result, str) and os.path.exists(result):
                        xml_path = result
                    elif isinstance(result, dict):
                        xml_path = result.get("results", {}).get("xml_output_path")
                        if xml_path and not os.path.exists(xml_path):
                            xml_path = None
                    if xml_path:
                        parsed_results = scanner._process_scan_results(xml_path, f"scan_{proto}_scan")
                        # Merge parsed_results into scanner.findings instead of overwriting
                        if "hosts" in parsed_results:
                            if "hosts" not in scanner.findings:
                                scanner.findings["hosts"] = []
                            # Merge hosts by IP
                            for new_host in parsed_results["hosts"]:
                                ip = new_host.get("ip")
                                existing_host = next((h for h in scanner.findings["hosts"] if h.get("ip") == ip), None)
                                if not existing_host:
                                    scanner.findings["hosts"].append(new_host)
                                else:
                                    # Merge ports
                                    existing_ports = existing_host.get("ports", [])
                                    for new_port in new_host.get("ports", []):
                                        if not any(
                                            p.get("id") == new_port.get("id") and p.get("protocol") == new_port.get("protocol")
                                            for p in existing_ports
                                        ):
                                            existing_ports.append(new_port)
                                    existing_host["ports"] = existing_ports
                    # Instead of calling scan_by_port_service here, submit it to the executor:
                    enum_futures[executor.submit(
                        scanner.scan_by_port_service,
                        max_workers=int(options['threads']),
                        protocol=proto
                    )] = proto
                    logging.info(f"[+] Submitted {proto.upper()} port-specific enumeration")
                except Exception as e:
                    logging.error(f"Error in {proto.upper()} scan: {e}")

            # Wait for all enumerations to finish
            for future in concurrent.futures.as_completed(enum_futures):
                proto = enum_futures[future]
                try:
                    future.result()
                    logging.info(f"[+] Completed {proto.upper()} port-specific enumeration")
                except Exception as e:
                    logging.error(f"Error in {proto.upper()} enumeration: {e}")
    
        findings = scanner.findings
        logging.info(f"[+] Initial scan and per-protocol enumeration complete.")

        # Get the count of discovered hosts and ports
        hosts_count = len(findings.get("hosts", []))
        ports_count = sum(len(host.get("ports", [])) for host in findings.get("hosts", []))
        logging.info(f"[+] Found {hosts_count} hosts with {ports_count} open ports.")
    try:
        ##########################
        ### SERVICE-BASED SCAN ###
        ##########################
        logging.info(f"[+] Starting service-specific enumeration")
        
        # Use the findings already populated by per-protocol enumeration
        findings = scanner.findings
        
        # Optional: Save the final results to a JSON file
        output_file = os.path.join(options['output_dir'], "spade_results.json")
        logging.debug(f"[!!!] Final Findings : {findings}")

        # Remove the _plugin_lock object
        for host in findings.get("hosts", []):
            for port in host.get("ports", []):
                if "_plugin_lock" in port:
                    del port["_plugin_lock"]

        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=4)
        logging.info(f"[+] Saved final results to {output_file}")
        
        # --- Reporter integration ---
        if args.report:
            # Determine template path
            if isinstance(args.report, str):
                template_path = args.report
            else:
                # Use default.html from templates folder
                template_path = os.path.join(os.path.dirname(__file__), "templates", "default.html")
            report_output = os.path.join(options['output_dir'], "spade_report.html")
            reporter = Reporter(template_path=template_path)
            reporter.generate_report(findings, output_file=report_output)
            logging.info(f"[+] HTML report generated at {report_output}")
    finally:
        # Stop the plugin monitor before exiting
        plugin_monitor.stop_monitoring()

if __name__ == "__main__":
    main()
