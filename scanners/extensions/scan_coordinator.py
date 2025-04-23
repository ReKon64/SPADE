# File: scanners/scan_coordinator.py
from core.imports import *
from scanners.scanner import Scanner
from scanners.nmap_parser import parse_nmap_xml

@Scanner.extend
def coordinate_scan_network(self):
    """
    Coordinates TCP and UDP scans and processes results after both complete.
    This is the main entry point for network scanning.
    """
    logging.info("Starting coordinated network scan (TCP and UDP)")
    
    tcp_result_path = None
    udp_result_path = None
    
    # Run TCP and UDP scans concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        tcp_future = executor.submit(self.scan_tcp_scan)
        udp_future = executor.submit(self.scan_udp_scan)
        
        # Wait for both to complete
        tcp_result_path = tcp_future.result()
        udp_result_path = udp_future.result()
    
    logging.info("Both TCP and UDP scans completed, processing results")
    
    # Process the scan results
    self.process_scan_results(tcp_result_path, udp_result_path)

@Scanner.extend
def process_scan_results(self, tcp_path, udp_path):
    """
    Process the TCP and UDP scan results after both scans have completed.
    
    Args:
        tcp_path: Path to TCP scan XML output
        udp_path: Path to UDP scan XML output
    """
    combined_results = {
        'tcp': {},
        'udp': {},
        'findings': []
    }
    
    try:
        # Process TCP results
        if tcp_path and os.path.exists(tcp_path):
            with open(tcp_path, 'r') as f:
                tcp_xml = f.read()
            tcp_results = parse_nmap_xml(tcp_xml)
            combined_results['tcp'] = tcp_results
            
            # Add findings
            for finding in tcp_results.get('findings', []):
                self.add_finding(finding['message'])
                combined_results['findings'].append({
                    'source': 'tcp',
                    **finding
                })
                
        # Process UDP results
        if udp_path and os.path.exists(udp_path):
            with open(udp_path, 'r') as f:
                udp_xml = f.read()
            udp_results = parse_nmap_xml(udp_xml)
            combined_results['udp'] = udp_results
            
            # Add findings
            for finding in udp_results.get('findings', []):
                self.add_finding(finding['message'])
                combined_results['findings'].append({
                    'source': 'udp',
                    **finding
                })
        
        # Save combined results to a JSON file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json', mode='w') as tmp_file:
            json_path = tmp_file.name
            json.dump(combined_results, tmp_file, indent=2)
            
        self.options['combined_results_path'] = json_path
        logging.info(f"Combined scan results saved to {json_path}")
        
        # Clean up individual scan result files
        self._cleanup_scan_files(tcp_path, udp_path)
        
        return combined_results
        
    except Exception as e:
        logging.error(f"Error processing scan results: {e}")
        self.add_finding(f"Error processing scan results: {e}")
        return {'error': str(e)}

@Scanner.extend
def _cleanup_scan_files(self, *file_paths):
    """Clean up temporary scan result files."""
    for path in file_paths:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
                logging.debug(f"Deleted temporary file: {path}")
            except Exception as e:
                logging.warning(f"Failed to delete temporary file {path}: {e}")
