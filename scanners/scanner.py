# File: scanners/scanner.py
from core.imports import *

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
            setattr(self, name, bound_method)
    
    def scan(self, max_workers=None, prioritized_methods=None):
        """
        Discover and execute scan methods in a controlled order.
        
        Args:
            max_workers (int, optional): Maximum number of worker threads.
            prioritized_methods (list, optional): List of method names to execute first and wait for completion
                                         before running other scan methods.
        
        Returns:
            list: Collected findings from all scan methods.
        """
        scan_methods = [
            method for method in dir(self)
            if method.startswith('scan_') and callable(getattr(self, method))
        ]
        
        # Handle prioritized methods if specified
        if prioritized_methods:
            # Filter out methods that don't exist
            valid_priority_methods = [
                method for method in prioritized_methods 
                if method in scan_methods
            ]
            
            # Execute priority methods first and wait for completion
            if valid_priority_methods:
                logging.debug(f"Executing prioritized methods: {valid_priority_methods}")
                self._execute_methods(valid_priority_methods)
                
                # Remove prioritized methods from the scan list
                remaining_methods = [m for m in scan_methods if m not in valid_priority_methods]
            else:
                remaining_methods = scan_methods
        else:
            remaining_methods = scan_methods
        
        # Execute remaining methods in parallel if any remain
        if remaining_methods:
            logging.debug(f"Executing remaining scan methods: {remaining_methods}")
            self._execute_methods(remaining_methods, max_workers)
        
        return self.findings
    
    def _execute_methods(self, method_names, max_workers=None):
        """
        Execute the specified methods, either sequentially or in parallel.
        
        Args:
            method_names (list): List of method names to execute
            max_workers (int, optional): If specified, methods are executed in parallel
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
                        future.result()  # Get result to catch any exceptions
                        logging.info(f"Completed scan: {method_name}")
                    except Exception as e:
                        logging.error(f"Error in {method_name}: {e}")
        else:
            # Execute sequentially
            for method_name in method_names:
                try:
                    self._execute_scan_method(method_name)
                    logging.info(f"Completed scan: {method_name}")
                except Exception as e:
                    logging.error(f"Error in {method_name}: {e}")
    
    def _execute_scan_method(self, method_name):
        """
        Helper method to execute a single scan method and handle exceptions.
        
        Args:
            method_name (str): Name of the scan method to execute.
        """
        logging.info(f"Starting scan: {method_name}")
        try:
            getattr(self, method_name)()
        except Exception as e:
            # Re-raise to be caught by the executor
            raise
    
    def add_finding(self, finding: str) -> None:
        """
        Thread-safe method to add a finding to the internal findings list.
        
        Args:
            finding (str): Description or result of a scan.
        """
        with self._findings_lock:
            self.findings.append(finding)
    
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
        return func
