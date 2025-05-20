# SPADE - Scalable Plug-and-play Auto Detection Engine

# Import components
from core.imports import *
from scanners.scanner import Scanner
# from reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="SPADE - Scalable Plug-and-play Auto Detection Engine")

    # Create mutually exclusive group for -t and -x
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="One or more IP / Domain")
    group.add_argument("-x", "--xml-input", help="Path to existing Nmap XML file to use as input (skips scanning and uses this for enumeration)")

    parser.add_argument("-tp", "--tcp-ports", default="-p-", help="Ports to scan. Passed directly to nmap. Default -p-")
    parser.add_argument("-up", "--udp-ports", default="--top-ports=100", help="WIP")

    parser.add_argument('-at', "--tcp-options", help="Additional flags to inject into the TCP nmap command")
    parser.add_argument('-au', "--udp-options", help="Additional flags to inject into the UDP nmap command")

    parser.add_argument("-T", "--threads", default=16, help="Number of threads scanner will use. I suggest 64")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-rt", "--realtime", action="store_true", help="Enable real time STDOUT for modules")
    parser.add_argument("-m", "--memory", action="store_true", help="Add memory usage to logging")

    parser.add_argument("-o", "--output", help="Output directory for reports and payloads. Defaults to CWD")
    
    parser.add_argument("--ferox-wordlists", nargs="+", help="One or more wordlists to use for feroxbuster (space separated not quoted).")

    args = parser.parse_args()

    # Idiot-proof ferox_wordlists: split if user quoted the list
    if args.ferox_wordlists and len(args.ferox_wordlists) == 1 and " " in args.ferox_wordlists[0]:
        logging.warning(
            "[!] You provided --ferox-wordlists as a quoted string. "
            "Splitting into multiple wordlists. Next time, do NOT quote the list!"
        )
        args.ferox_wordlists = args.ferox_wordlists[0].split()

    # Configure logging
    if args.memory:
        from core.logging import MemoryUsageFormatter
        format = '%(asctime)s - %(levelname)s - [MEM: %(memory_usage)s] - %(message)s'
        if args.realtime:
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
    else:
        format = '%(asctime)s - %(levelname)s - %(message)s'
        if args.realtime:
            log_level = 15
        elif args.verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        logging.basicConfig(level=log_level, format=format)

    # Options dictionary
    options = {
        'output_dir': args.output or os.getcwd(),
        'verbose': args.verbose,
        'realtime': args.realtime,
        'threads': args.threads,
        'target': args.target,
        'tcp_ports': args.tcp_ports,
        'udp_ports': args.udp_ports,
        'tcp_options': args.tcp_options,
        'udp_options': args.udp_options,
        'ferox_wordlists': args.ferox_wordlists,
    }

    # Load all scanner extensions
    Scanner.load_extensions()
    scanner = Scanner(options)

    # If --xml-input is provided, parse the XML and skip initial scans
    if args.xml_input:
        logging.info(f"[+] Parsing Nmap XML input file: {args.xml_input}")
        with open(args.xml_input, 'r') as f:
            xml_data = f.read()
        from scanners.nmap_parser import parse_nmap_xml
        findings = parse_nmap_xml(xml_data)
        scanner.findings = findings  # Set findings for service enumeration
        logging.info(f"[+] Parsed {len(findings.get('hosts', []))} hosts from XML input.")
    else:
        # Normal scan flow
        if not args.target:
            parser.error("the following arguments are required: -t/--target (unless --xml-input is used)")
        logging.info(f"[+] Starting initial scans against {options['target']}")
        logging.debug(f"Scanner initialized with options: {scanner.options}")
        
        # Run the initial TCP and UDP scans
        findings = scanner.scan(
            max_workers=int(options['threads']),
            prioritized_methods=['scan_tcp_scan', 'scan_udp_scan'],
            prefixes=['scan_'],
        )
        logging.info(f"[?] Finding: {findings}")
        logging.info(f"[+] Initial scan complete.")
        
        # Get the count of discovered hosts and ports
        hosts_count = len(findings.get("hosts", []))
        ports_count = sum(len(host.get("ports", [])) for host in findings.get("hosts", []))
        logging.info(f"[+] Found {hosts_count} hosts with {ports_count} open ports.")

    ##########################
    ### SERVICE-BASED SCAN ###
    ##########################
    logging.info(f"[+] Starting service-specific enumeration")
    
    # Use our new extension to scan by port/service
    findings = scanner.scan_by_port_service(max_workers=int(options['threads']))
    
    # Output findings summary
    if "services" in findings:
        for service_name, service_results in findings.get("services", {}).items():
            logging.info(f"[+] Testing service output {service_name} : {service_results}")
            logging.info(f"{findings}")
    else:
        logging.info("[!!!] if services failed")
            
    
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

if __name__ == "__main__":
    main()
