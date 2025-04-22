# SPADE - Scalable Plug-and-play Auto Detection Engine

# Import components
from core.imports import *
from scanners.scanner import Scanner
# from reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="SPADE - Scalable Plug-and-play Auto Detection Engine")
    parser.add_argument("-t", "--target", action="store_true", help="One or more IP / Domain")
    parser.add_argument("-p", "--ports", default="-p-", help="Ports to scan. Passed directly to nmap")
    parser.add_argument("-T", "--threads", default=16, help="Number of threads scanner will use. I suggest 64")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Output directory for reports and payloads")
    parser.add_argument('-a', "--additional", help="Additional flags to inject into the nmap command")
    
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    options = {
        'output_dir': args.output or os.getcwd(),
        'verbose': args.verbose,
        'threads': args.threads,
        'target': args.target,
        'ports': args.ports,
        'additional': args.additional,
    }
    
    # Create instances of core components
    scanner = Scanner(options)
    #reporter = Reporter(options)
 
    if args.scan or args.auto:
        logging.info("[+] Starting system scan...")
        logging.debug(f"Scanner initialized with options: {scanner.options}")
        findings = scanner.scan()
        
        logging.info(f"[+] Scan complete. Found {len(findings)} items.")
        #report_file = reporter.generate(findings)
        #logging.info(f"[+] Report generated: {report_file}")


if __name__ == "__main__":
    main()