# SPADE - Scalable Plug-and-play Auto Detection Engine

# Import components
from core.imports import *
from scanners.scanner import Scanner
from core.logging import ContextPrefixFilter
# from reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="SPADE - Scalable Plug-and-play Auto Detection Engine")

    #group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-t", "--target", help="One or more IP / Domain")
    parser.add_argument("-x", "--xml-input", help="Path to existing Nmap XML file to use as input (skips scanning and uses this for enumeration)")

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
    parser.add_argument("--google-api-key", help="Google Custom Search API key for product search plugins")
    parser.add_argument("--google-cse-id", help="Google Custom Search Engine ID for product search plugins")

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
        format = '%(asctime)s - %(levelname)s - [MEM: %(memory_usage)s] - %(hostport)s - %(prefix)s - %(message)s'
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
        root_logger.addFilter(ContextPrefixFilter())
    else:
        format = '%(asctime)s - %(levelname)s - %(hostport)s - %(prefix)s - %(message)s'
        if args.realtime and args.verbose:
            log_level = min(logging.DEBUG, 15)  # 10
        elif args.realtime:
            log_level = 15
        elif args.verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        logging.basicConfig(level=log_level, format=format)
        logging.getLogger().addFilter(ContextPrefixFilter())
    
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
        'google_api_key': args.google_api_key,
        'google_cse_id': args.google_cse_id,
    }

    # Load all scanner extensions
    Scanner.load_extensions()
    scanner = Scanner(options)

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

if __name__ == "__main__":
    main()
