# File: scanners/scanner.py
from core.imports import *
from scanners.nmap_parser import parse_nmap_xml
class Scanner:
    """
    Base Scanner class supporting auto-discovery of scan methods with threaded execution.
    Method Types:
    - Scan Methods: Prefixed with 'scan_', auto-executed via `scan()`
    - Extension Methods: Registered with @Scanner.extend
    - Helper Methods: Support functions (e.g., add_finding)
    Attributes:
        findings (list): Collected scan results
        options (dict): Scanner-specific configuration
        _extensions (dict): Registered extension methods (class-level)
        _findings_lock (threading.Lock): Lock for thread-safe findings updates
    """
    _extensions = {}
    
    def __init__(self, options: dict):
        self.findings = []
        self.options = options
        self._findings_lock = threading.Lock()
        
        # Bind registered extension methods to the instance
        for name, func in self._extensions.items():
            bound_method = func.__get__(self, self.__class__)
            logging.debug(f"Loaded Bound: {bound_method}")
            setattr(self, name, bound_method)
    
    @classmethod
    def load_extensions(cls, extensions_path="scanners.extensions"):
        """
        Dynamically load all extension modules from the specified path.
        
        Args:
            extensions_path (str): The Python module path to the extensions directory.
        """
        package = importlib.import_module(extensions_path)
        package_path = os.path.dirname(package.__file__)
        logging.debug(f"Package Path: {package_path}")
        for _, module_name, _ in pkgutil.iter_modules([package_path]):
            full_module_name = f"{extensions_path}.{module_name}"
            importlib.import_module(full_module_name)
        logging.debug(f"Loaded extension module: {full_module_name}")

    def scan(self, max_workers=None, prioritized_methods=None):
        """
        Discover and execute scan methods in a controlled order.
        
        Args:
            max_workers (int, optional): Maximum number of worker threads.
            prioritized_methods (list, optional): List of method names to execute first and process results.
        
        Returns:
            list: Collected findings from all scan methods.
        """
        # Discover all scan methods
        scan_methods = [
            method for method in dir(self)
            if method.startswith('scan_') and callable(getattr(self, method))
        ]
        logging.debug(f"Discovered scan methods: {scan_methods}")

        # Separate prioritized methods from remaining methods
        prioritized_methods = prioritized_methods or []
        valid_prioritized_methods = [m for m in prioritized_methods if m in scan_methods]
        remaining_methods = [m for m in scan_methods if m not in valid_prioritized_methods]

        # Execute prioritized methods first
        if valid_prioritized_methods:
            logging.info(f"Executing prioritized methods: {valid_prioritized_methods}")
            self._execute_methods(valid_prioritized_methods, max_workers)

        # Execute remaining methods
        if remaining_methods:
            logging.info(f"Executing remaining methods: {remaining_methods}")
            self._execute_methods(remaining_methods, max_workers)

        return self.findings
    
    def _execute_methods(self, method_names, max_workers=None):
        """
        Execute the specified methods, either sequentially or in parallel, and process results if applicable.
        
        Args:
            method_names (list): List of method names to execute.
            max_workers (int, optional): If specified, methods are executed in parallel.
        """
        if max_workers:
            # Execute in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._execute_scan_method, method_name): method_name
                    for method_name in method_names
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    method_name = futures[future]
                    try:
                        result_path = future.result()  # Get result to catch any exceptions
                        logging.info(f"Completed scan: {method_name}")
                        
                        # Process results if the method produces output
                        if result_path and os.path.exists(result_path):
                            logging.info(f"Processing results for {method_name}")
                            with open(result_path, 'r') as f:
                                xml_data = f.read()
                            parsed_results = parse_nmap_xml(xml_data)
                            self._store_findings(parsed_results)
                    except Exception as e:
                        logging.error(f"Error in {method_name}: {e}")
        else:
            # Execute sequentially
            for method_name in method_names:
                try:
                    result_path = self._execute_scan_method(method_name)
                    logging.info(f"Completed scan: {method_name}")
                    
                    # Process results if the method produces output
                    if result_path and os.path.exists(result_path):
                        logging.info(f"Processing results for {method_name}")
                        with open(result_path, 'r') as f:
                            xml_data = f.read()
                        parsed_results = parse_nmap_xml(xml_data)
                        self._store_findings(parsed_results)
                except Exception as e:
                    logging.error(f"Error in {method_name}: {e}")
    
    def _execute_scan_method(self, method_name):
        """
        Helper method to execute a single scan method and handle exceptions.
        
        Args:
            method_name (str): Name of the scan method to execute.
        
        Returns:
            str: Path to the result file (if applicable).
        """
        logging.info(f"Starting scan: {method_name}")
        try:
            result = getattr(self, method_name)()
            return result  # Return the result path if the method produces one
        except Exception as e:
            logging.error(f"Error in method {method_name}: {e}")
            return None
    
    def add_finding(self, finding: str) -> None:
        """
        Thread-safe method to add a finding to the internal findings list.
        
        Args:
            finding (str): Description or result of a scan.
        """
        with self._findings_lock:
            self.findings.append(finding)
    
    def _store_findings(self, parsed_results):
        """
        Store parsed findings into the findings list.
        
        Args:
            parsed_results (dict): Parsed results from Nmap XML.
        """
        findings = parsed_results.get('findings', [])
        with self._findings_lock:
            for finding in findings:
                self.findings.append(finding['message'])
    
    @classmethod
    def extend(cls, func):
        """
        Class decorator to register new extension methods.
        
        Usage:
            @Scanner.extend
            def custom_method(self):
                ...
        """
        cls._extensions[func.__name__] = func
        logging.debug(f"Registering extension: {func.__name__}")

        return func
