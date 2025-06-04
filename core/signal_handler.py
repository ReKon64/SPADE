from imports import *
from core.plugin_monitor import plugin_monitor

class GracefulExitHandler:
    """
    Handler for gracefully exiting when receiving interrupt signals.
    Saves scan results and generates a report before exiting.
    """
    
    def __init__(self):
        self.scanner = None
        self.args = None
        self.options = {}
    
    def register(self, scanner=None, args=None):
        """Register scanner and args with the handler"""
        self.scanner = scanner
        self.args = args
        if scanner and hasattr(scanner, 'options'):
            self.options = scanner.options
            
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        # SIGHUP is not available on Windows
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_signal)
        
        logging.debug("Signal handlers registered for graceful shutdown")
    
    def _handle_signal(self, sig, frame):
        """Handle termination signals by saving results before exiting"""
        logging.info("\n[!] Received interrupt signal. Attempting to save results before exiting...")
        
        if self.scanner and hasattr(self.scanner, 'findings'):
            try:
                # Get output directory from options or use current directory
                output_dir = self.options.get('output_dir', os.getcwd())
                
                # Save results to JSON
                output_file = os.path.join(output_dir, "spade_interrupted_results.json")
                
                # Remove locks from results
                findings = self.scanner.findings
                for host in findings.get("hosts", []):
                    for port in host.get("ports", []):
                        if "_plugin_lock" in port:
                            del port["_plugin_lock"]
                
                # Write JSON
                with open(output_file, 'w') as f:
                    json.dump(findings, f, indent=4)
                logging.info(f"[+] Saved interrupted scan results to {output_file}")
                
                # Generate report if requested
                if self.args and hasattr(self.args, 'report') and self.args.report:
                    try:
                        # Determine template path
                        if isinstance(self.args.report, str):
                            template_path = self.args.report
                        else:
                            # Use default.html from templates folder
                            template_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                                         "templates", "default.html")
                        
                        report_output = os.path.join(output_dir, "spade_interrupted_report.html")
                        from core.reporter import Reporter
                        reporter = Reporter(template_path=template_path)
                        reporter.generate_report(findings, output_file=report_output)
                        logging.info(f"[+] HTML report generated at {report_output}")
                    except Exception as e:
                        logging.error(f"[!] Error generating report during interrupt: {e}")
            except Exception as e:
                logging.error(f"[!] Error saving results during interrupt: {e}")
            
            # Stop the plugin monitor
            plugin_monitor.stop_monitoring()
        
        logging.info("[!] Exiting due to interrupt...")

# Global instance for easy import
handler = GracefulExitHandler()