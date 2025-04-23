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
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
       
    # I like the extra layer of abstraction and control compared to just raw args.opt alright?
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


    # Create instances of core components
    Scanner.load_extensions()
    scanner = Scanner(options)

    # reporter = Reporter(options)

    logging.info(f"[+] Starting scan against {options['target']}")
    logging.debug(f"Scanner initialized with options: {scanner.options}")
    findings = scanner.scan(
        max_workers=int(options['threads']),
        prioritized_methods=['scan_tcp_scan', 'scan_udp_scan']
    )
    logging.info(f"[+] Scan complete. Found {len(findings)} items.")
    #report_file = reporter.generate(findings)
    #logging.info(f"[+] Report generated: {report_file}")


if __name__ == "__main__":
    main()