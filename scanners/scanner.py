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
        self.findings = {}
        self.options = options
        self._findings_lock = threading.Lock()
        
        # Bind registered extension methods to the instance
        for name, func in self._extensions.items():
            bound_method = func.__get__(self, self.__class__)
            # Commented since it clutters a lot and each time
            #logging.debug(f"Loaded Bound: {bound_method}")
            setattr(self, name, bound_method)
    
    @classmethod
    # Next time I build a scanner, load this dynamically
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
            try:
                full_module_name = f"{extensions_path}.{module_name}"
                importlib.import_module(full_module_name)
            except Exception as e:
                logging.info(f"[!] Skipping {full_module_name} due to exception : {e}")
                continue
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

        Returns:
            dict: Mapping of method_name to result (for plugin aggregation).
        """
        plugin_results = {}

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
                        result = future.result()  # Get result to catch any exceptions
                        logging.info(f"Completed scan: {method_name}")

                        # Process results if the method produces output
                        if isinstance(result, str) and os.path.exists(result):
                            self._process_scan_results(result, method_name)
                            # Optionally, you could parse and store results here if needed
                        elif isinstance(result, dict):
                            plugin_results[method_name] = result
                    except Exception as e:
                        logging.error(f"Error in {method_name}: {e}")
        else:
            # Execute sequentially
            for method_name in method_names:
                try:
                    result = self._reflection_execute_method(method_name)
                    logging.info(f"Completed scan: {method_name}")

                    if isinstance(result, str) and os.path.exists(result):
                        self._process_scan_results(result, method_name)
                    elif isinstance(result, dict):
                        plugin_results[method_name] = result
                except Exception as e:
                    logging.error(f"Error in {method_name}: {e}")

        return plugin_results
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
        self.findings.update(parsed_results)
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
            re.compile(r"^ftp$"):      "enum_ftp",
            re.compile(r"^http.*"):    "enum_http",
            re.compile(r"^(smb|netbios)"): "enum_smb",
            re.compile(r"^ssh$"):      "enum_ssh",
            re.compile(r"^(rpc|msrpc)"):   "enum_rpc",
            re.compile(r"^(dns|domain)$"): "enum_dns",
            re.compile(r"ldap") : "enum_ldap",
            re.compile(r".*"):         "enum_generic",
        }
        
        # Track services that need to be enumerated
        port_service_pairs = []
        
        # First, find all port:service pairs from the findings
        hosts = self.findings.get("hosts", [])
        logging.debug(f"[*] Service scan used entry data : {hosts}")
        for host in hosts:
            for port in host.get("ports", []):
                # Add a per-port lock if not already present
                if "_plugin_lock" not in port:
                    port["_plugin_lock"] = threading.Lock()
                service_name = port.get("service", {}).get("name", "").lower()
                for pattern, enum_prefix in service_prefix_map.items():
                    if pattern.search(service_name):
                        port_data = {
                            "host": host.get("ip", ""),
                            "port_id": port.get("id", ""),
                            "protocol": port.get("protocol", ""),
                            "service": service_name,
                            "enum_prefix": enum_prefix,
                            "port_obj": port, # Reference to port dict
                            "host_json": host,
                        }
                        port_service_pairs.append(port_data)
                        logging.debug(f"[*] Will scan with prefix {enum_prefix} on {port_data['host']}:{port_data['port_id']} with {enum_prefix}")
                        # Break so you don’t match multiple prefixes for the same svc
                        break
        
        # If no services found, return early
        if not port_service_pairs:
            logging.info("[+] No services found to enumerate")
            return self.findings

        
        logging.info(f"[+] Found {len(port_service_pairs)} port:service pairs")
        
        # For each port:service pair, run a targeted scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or 10) as executor:
            logging.debug(f"[THREADS] scan_by_port_service using {max_workers or 10} threads for port/service enumeration")
            futures = {}
            for port_data in port_service_pairs:
                #current_port_data = copy.deepcopy(port_data)
                temp_options = copy.deepcopy(self.options)
                temp_options["current_port"] = port_data
                futures[executor.submit(
                    self._scan_individual_port,
                    port_data=port_data,
                    options=temp_options,
                    max_workers=max_workers
                )] = port_data
                
                # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                port_data = futures[future]
                try:
                    plugin_results = future.result()
                    port_obj = port_data["port_obj"]
                    with port_obj["_plugin_lock"]:
                        if "plugins" not in port_obj:
                            port_obj["plugins"] = {}
                        for plugin_name, result in plugin_results.items():
                            port_obj["plugins"][plugin_name] = result
                except Exception as e:
                    logging.error(f"Error processing scan for {port_data['service']} on {port_data['host']}:{port_data['port_id']}: {e}")
        
        logging.info(f"[+] Completed all port-specific enumeration")
        return self.findings

    def _scan_individual_port(self, port_data, options, max_workers=None):
        """
        Scan a specific port with the appropriate enumeration prefix, respecting plugin dependencies.

        Args:
            port_data (dict): Information about the port to scan
            options (dict): Scanner options with port-specific data
            max_workers (int, optional): Maximum number of worker threads

        Returns:
            dict: Results from the scan
        """
        enum_prefix = port_data["enum_prefix"]
        temp_scanner = Scanner(options)
        methods = [
            method for method in dir(temp_scanner)
            if method.startswith(enum_prefix) and callable(getattr(temp_scanner, method))
        ]
        if not methods:
            logging.warning(f"No methods found with prefix {enum_prefix}")
            return {}
        return self._execute_plugins_with_scheduler(temp_scanner, methods, max_workers=max_workers)

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
    
    def _run_plugin_with_deps(self, plugin_name, temp_scanner, plugin_results):
        plugin_func = getattr(temp_scanner, plugin_name)
        depends_on = getattr(plugin_func, "depends_on", [])
        for dep in depends_on:
            if dep not in plugin_results:
                self._run_plugin_with_deps(dep, temp_scanner, plugin_results)
        # Now run the plugin itself
        if plugin_name not in plugin_results:
            plugin_results[plugin_name] = plugin_func()

    def _execute_plugins_with_scheduler(self, temp_scanner, methods, max_workers=None):
        import concurrent.futures
        graph = self._build_plugin_dependency_graph(temp_scanner, methods)
        # Reverse graph for dependents
        dependents = {k: set() for k in graph}
        for k, deps in graph.items():
            for dep in deps:
                dependents.setdefault(dep, set()).add(k)
        # Track completed plugins
        completed = set()
        results = {}
        # Plugins with no dependencies
        ready = [m for m in methods if not graph[m]]

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or 4) as executor:
            futures = {}
            while ready or futures:
                # Submit all ready plugins
                for plugin in ready:
                    futures[executor.submit(getattr(temp_scanner, plugin))] = plugin
                ready = []
                # Wait for any to finish
                for future in concurrent.futures.as_completed(futures):
                    plugin = futures.pop(future)
                    results[plugin] = future.result()
                    completed.add(plugin)
                    # Check dependents
                    for dep in dependents.get(plugin, []):
                        if all(d in completed for d in graph[dep]) and dep not in completed and dep not in ready:
                            ready.append(dep)
                    break  # Only process one at a time to allow new ready plugins
        return results

    def _build_plugin_dependency_graph(self, temp_scanner, methods):
        graph = {}
        for method in methods:
            func = getattr(temp_scanner, method)
            deps = getattr(func, "depends_on", [])
            graph[method] = deps
        logging.debug(f"[PLUGIN DEP GRAPH] Built dependency graph: {graph}")
        return graph

    def _topo_sort_plugins(self, graph):
        from collections import deque, defaultdict

        in_degree = defaultdict(int)
        for node, deps in graph.items():
            for dep in deps:
                in_degree[dep] += 1  # increment in-degree for dependency

        # Nodes with no dependencies (in-degree 0)
        queue = deque([node for node in graph if in_degree[node] == 0])
        sorted_plugins = []

        while queue:
            node = queue.popleft()
            sorted_plugins.append(node)
            for dependent in graph:
                if node in graph[dependent]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)

        if len(sorted_plugins) != len(graph):
            raise Exception("Cycle detected in plugin dependencies!")
        return sorted_plugins
