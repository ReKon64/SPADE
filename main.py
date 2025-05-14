# SPADE - Scalable Plug-and-play Auto Detection Engine

# Import components
from core.imports import *
from scanners.scanner import Scanner
# from reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="SPADE - Scalable Plug-and-play Auto Detection Engine")
    parser.add_argument("-t", "--target", help="One or more IP / Domain", required=True)
    
    parser.add_argument("-tp", "--tcp_ports", default="-p-", help="Ports to scan. Passed directly to nmap. Default -p-")
    parser.add_argument("-up", "--udp_ports", default="--top-ports=100", help="WIP")

    parser.add_argument("-T", "--threads", default=16, help="Number of threads scanner will use. I suggest 64")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Output directory for reports and payloads")
    parser.add_argument('-at', "--tcp_options", help="Additional flags to inject into the TCP nmap command")
    parser.add_argument('-au', "--udp_options", help="Additional flags to inject into the UDP nmap command")
    args = parser.parse_args()


    # Configure logging
    format='%(asctime)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(level=log_level, format=format)

    # Options dictionary
    options = {
        'output_dir': args.output or os.getcwd(),
        'verbose': args.verbose,
        'threads': args.threads,
        'target': args.target,
        'tcp_ports': args.tcp_ports,
        'udp_ports': args.udp_ports,
        'tcp_options': args.tcp_options,
        'udp_options': args.udp_options,
    }

    # Load all scanner extensions
    Scanner.load_extensions()
    scanner = Scanner(options)

    ####################
    ### INITIAL SCAN ###
    ####################
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
            logging.info(f"[+] {service_name}: Found {len(service_results)} instances")
    
    # Optional: Save the final results to a JSON file
    output_file = os.path.join(options['output_dir'], "spade_results.json")
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=4)
    logging.info(f"[+] Saved final results to {output_file}")

if __name__ == "__main__":
    main()
