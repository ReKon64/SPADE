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

# This can be reimplemented to use a different prefix.
# I'd have to pass a different string that "scanners.extensions" for example for bruteforce etc.


    def scan(self, max_workers=None, prioritized_methods=None, prefixes=None):
        """
        Discover and execute methods matching any of the specified prefixes in a controlled order.
        
        Args:
            max_workers (int, optional): Maximum number of worker threads.
            prioritized_methods (list, optional): List of method names to execute first and process results.
            prefixes (list): A list of prefixes used to identify methods to be executed (e.g., ['scan_', 'brute_']).
        
        Returns:
            list: Collected findings from all scan methods.
        """
        try:
            if not prefixes or not isinstance(prefixes, list):
                raise ValueError("The 'prefixes' argument must be a non-empty list of strings.")

            # Discover all methods matching any of the prefixes
            discovered_methods = [
                method for method in dir(self)
                if any(method.startswith(prefix) for prefix in prefixes) and callable(getattr(self, method))
            ]
            logging.debug(f"Discovered methods with prefixes {prefixes}: {discovered_methods}")

            # Separate prioritized methods from remaining methods
            prioritized_methods = prioritized_methods or []
            valid_prioritized_methods = [m for m in prioritized_methods if m in discovered_methods]
            remaining_methods = [m for m in discovered_methods if m not in valid_prioritized_methods]

            # Execute prioritized methods first
            if valid_prioritized_methods:
                self._execute_methods(method_names=valid_prioritized_methods, max_workers=max_workers)

            # Execute remaining methods
            if remaining_methods:
                logging.info(f"Executing remaining methods: {remaining_methods}")
                self._execute_methods(method_names=remaining_methods, max_workers=max_workers)

        except ValueError as e:
            logging.error(f"Invalid prefixes argument: {e}")
            return []
        return self.findings
    
    
    def _reflection_execute_method(self, method_name):
        """
        Dynamically execute a method via reflection by its name.
        
        Args:
            method_name (str): Name of the method to execute.
        
        Returns:
            Any: The result of the method (e.g., path to the result file).
        """
        logging.info(f"Executing method: {method_name}")
        try:
            # Dynamically call the method by its name
            method = getattr(self, method_name)
            return method()
        except AttributeError:
            logging.error(f"Method {method_name} does not exist.")
            raise
        except Exception as e:
            logging.error(f"Error executing method {method_name}: {e}")
            raise

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
                    executor.submit(self._reflection_execute_method, method_name): method_name
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
                            self._process_scan_results(result_path, method_name)
                    except Exception as e:
                        logging.error(f"Error in {method_name}: {e}")
        else:
            # Execute sequentially
            for method_name in method_names:
                try:
                    result_path = self._reflection_execute_method(method_name)
                    logging.info(f"Completed scan: {method_name}")
                    
                    # Process results if the method produces output
                    if result_path and os.path.exists(result_path):
                        self._process_scan_results(result_path, method_name)
                except Exception as e:
                    logging.error(f"Error in {method_name}: {e}")
    # seperate prefix for tcp 
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
        logging.debug(f"Findings size: {getsizeof(self.findings)}")

    def _cleanup_scan_files(self, *file_paths):
        """
        Delete temporary scan result files.
        
        Args:
            file_paths (list): List of file paths to delete.
        """
        for file_path in file_paths:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logging.info(f"Deleted temporary file: {file_path}")
                except Exception as e:
                    logging.error(f"Failed to delete file {file_path}: {e}")


    # Repurpose this later for general parsing ?
    def _process_scan_results(self, result_path, method_name):
        """
        Process the scan results by parsing the XML, storing findings, and optionally saving to JSON.
        
        Args:
            result_path (str): Path to the scan result file.
            method_name (str): Name of the scan method that produced the result.
        """
        try:
            logging.info(f"Processing results for {method_name}")
            with open(result_path, 'r') as f:
                xml_data = f.read()
            logging.debug(f"{method_name} XML Path: {result_path}")
            
            # Parse the XML data. 
            # Implement a check so this runs only for XML files lol ?
            parsed_results = parse_nmap_xml(xml_data)
            
            # Store findings in the Scanner instance
            self._store_findings(parsed_results)
            
            # Save parsed results to a JSON file
            json_output_path = os.path.join(self.options['output_dir'], f"{method_name}_results.json")
            with open(json_output_path, 'w') as json_file:
                json.dump(parsed_results, json_file, indent=4)
            logging.info(f"Saved parsed results to JSON: {json_output_path}")
            
            # Optionally clean up the result file
            self._cleanup_scan_files(result_path)
        except Exception as e:
            logging.error(f"Error processing results for {method_name}: {e}")
        
        return self.findings


    def scan_by_port_service(self, max_workers=None):
        """
        Scan and enumerate services by port and service type.
        This method overrides the default scan behavior to handle port-specific enumeration.
        
        Args:
            max_workers (int, optional): Maximum number of worker threads.
        
        Returns:
            dict: Combined findings from all port-specific scans.
        """
        logging.info("[+] Starting port-specific enumeration")
        
        # Define a map of service names to their enum prefixes
        service_prefix_map = {
            "ftp": "enum_ftp",
            "http": "enum_http", 
            "https": "enum_http",
            "smb": "enum_smb",
            "ssh": "enum_ssh",
            "rpc": "enum_rpc",
            # Add more services as needed
        }
        
        # Track services that need to be enumerated
        services_to_scan = set()
        port_service_pairs = []
        
        # First, find all port:service pairs from the findings
        hosts = self.findings.get("hosts", [])
        for host in hosts:
            for port in host.get("ports", []):
                service_name = port.get("service", {}).get("name", "").lower()
                
                # Check if this service has a matching prefix
                for key in service_prefix_map:
                    if service_name == key or service_name.startswith(key):
                        enum_prefix = service_prefix_map[key]
                        services_to_scan.add(enum_prefix)
                        
                        # Store the port details and service name for later use
                        port_data = {
                            "host": host.get("addr", ""),
                            "port_id": port.get("portid", ""),
                            "protocol": port.get("protocol", ""),
                            "service": service_name,
                            "enum_prefix": enum_prefix
                        }
                        port_service_pairs.append(port_data)
                        logging.debug(f"Will scan {service_name} on {host.get('addr')}:{port.get('portid')}")
        
        # If no services found, return early
        if not services_to_scan:
            logging.info("[+] No services found to enumerate")
            return self.findings
        
        logging.info(f"[+] Services to scan: {services_to_scan}")
        logging.info(f"[+] Found {len(port_service_pairs)} port:service pairs")
        
        # Create a placeholder for results
        all_results = {"findings": [], "services": {}}
        
        # For each port:service pair, run a targeted scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or 10) as executor:
            futures = {}
            
            for port_data in port_service_pairs:
                # Create a copy of the port data to avoid race conditions
                current_port_data = copy.deepcopy(port_data)
                
                # Update the options with the current port data
                temp_options = copy.deepcopy(self.options)
                temp_options["current_port"] = current_port_data
                
                # Submit the job to scan this port
                futures[executor.submit(
                    self._scan_individual_port, 
                    port_data=current_port_data, 
                    options=temp_options, 
                    max_workers=max_workers
                )] = current_port_data
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                port_data = futures[future]
                try:
                    port_result = future.result()
                    if port_result:
                        service_name = port_data["service"]
                        if service_name not in all_results["services"]:
                            all_results["services"][service_name] = []
                        
                        all_results["services"][service_name].append({
                            "host": port_data["host"],
                            "port": port_data["port_id"],
                            "results": port_result
                        })
                        
                        # Also add to the overall findings
                        all_results["findings"].extend(port_result.get("findings", []))
                except Exception as e:
                    logging.error(f"Error processing scan for {port_data['service']} on {port_data['host']}:{port_data['port_id']}: {e}")
        
        # Combine the results with the main findings
        with self._findings_lock:
            # Update findings with service-specific results
            if "services" not in self.findings:
                self.findings["services"] = {}
            
            for service_name, results in all_results["services"].items():
                if service_name not in self.findings["services"]:
                    self.findings["services"][service_name] = []
                self.findings["services"][service_name].extend(results)
        
        logging.info(f"[+] Completed all port-specific enumeration")
        return self.findings

    def _scan_individual_port(self, port_data, options, max_workers=None):
        """
        Scan a specific port with the appropriate enumeration prefix.
        
        Args:
            port_data (dict): Information about the port to scan
            options (dict): Scanner options with port-specific data
            max_workers (int, optional): Maximum number of worker threads
            
        Returns:
            dict: Results from the scan
        """
        enum_prefix = port_data["enum_prefix"]
        host = port_data["host"]
        port_id = port_data["port_id"]
        service = port_data["service"]
        
        logging.info(f"[+] Scanning {service} on {host}:{port_id} with prefix {enum_prefix}")
        
        # Create a temporary Scanner instance with the specific port options
        temp_scanner = Scanner(options)
        
        # Get all methods with the specified enum prefix
        methods = [
            method for method in dir(temp_scanner)
            if method.startswith(enum_prefix) and callable(getattr(temp_scanner, method))
        ]
        
        if not methods:
            logging.warning(f"No methods found with prefix {enum_prefix}")
            return {}
        
        logging.debug(f"Found methods for {enum_prefix}: {methods}")
        
        # Run the methods against this specific port
        results = {"findings": []}
        
        # Run each method (could be parallelized further if needed)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or 5) as executor:
            futures = {}
            for method_name in methods:
                futures[executor.submit(temp_scanner._reflection_execute_method, method_name)] = method_name
                
            for future in concurrent.futures.as_completed(futures):
                method_name = futures[future]
                try:
                    result = future.result()
                    if result:
                        logging.info(f"Scan {method_name} completed for {service} on {host}:{port_id}")
                        # Process result if needed
                        if isinstance(result, dict):
                            results["findings"].extend(result.get("findings", []))
                        elif isinstance(result, list):
                            results["findings"].extend(result)
                        elif isinstance(result, str) and os.path.exists(result):
                            # It's a file path, try to process it
                            temp_scanner._process_scan_results(result, method_name)
                except Exception as e:
                    logging.error(f"Error in method {method_name} for {service} on {host}:{port_id}: {e}")
        
        return results

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
