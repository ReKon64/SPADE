# File: scanners/scanner.py
from core.imports import *
from scanners.nmap_parser import parse_nmap_xml
from core.plugin_monitor import plugin_monitor

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
        
        # Start the plugin monitor
        plugin_monitor.start_monitoring()
        
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


    def scan(self, max_workers=None, prefixes=None):
        """
        Discover and execute methods matching any of the specified prefixes in a controlled order.
        Args:
            max_workers (int, optional): Maximum number of worker threads.
            prefixes (list): A list of prefixes used to identify methods to be executed (e.g., ['scan_', 'brute_']).
        Returns:
            dict: Collected findings from all scan methods.
        """
        try:
            if not prefixes or not isinstance(prefixes, list):
                raise ValueError("The 'prefixes' argument must be a non-empty list of strings.")

            # Discover all methods matching any of the prefixes
            discovered_methods = [
                method for method in dir(self)
                if any(method.startswith(prefix) for prefix in prefixes)
                and callable(getattr(self, method))
                and method != "scan_by_port_service"  # <-- Add this line
            ]
            # Sort so brute_ plugins are last
            discovered_methods.sort(key=lambda m: m.startswith("brute_"))
            logging.debug(f"Discovered methods with prefixes {prefixes}: {discovered_methods}")

            # Execute all discovered methods (scan plugins and others)
            plugin_results = self._execute_methods(method_names=discovered_methods, max_workers=max_workers)

            # After scan plugins, parse their XML output and update self.findings
            for method_name, result in plugin_results.items():
                if (
                    isinstance(result, dict)
                    and "results" in result
                    and isinstance(result["results"], dict)
                    and "xml_output_path" in result["results"]
                ):
                    xml_path = result["results"]["xml_output_path"]
                    if os.path.exists(xml_path):
                        self._process_scan_results(xml_path, method_name)
                else:
                    logging.warning(f"[WARNING] {method_name} did not return a valid XML output path in results: {result}")

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

        # Add this before the main scheduling loop
        if hasattr(self, "_virtual_scan_plugins"):
            for scan_plugin in self._virtual_scan_plugins:
                plugin_results[scan_plugin] = {"virtual": True}

        return plugin_results
    # seperate prefix for tcp 
    def _store_findings(self, parsed_results):
        """
        Store parsed findings into the findings list.

        Args:
            parsed_results (dict): Parsed results from Nmap XML.
        """
        hosts = parsed_results.get('hosts', [])
        with self._findings_lock:
            if "hosts" not in self.findings:
                self.findings["hosts"] = []
            # Merge hosts by IP, merge ports by id/protocol
            for new_host in hosts:
                ip = new_host.get("ip")
                existing_host = next((h for h in self.findings["hosts"] if h.get("ip") == ip), None)
                if not existing_host:
                    logging.debug(f"[MERGE] Adding new host: {ip}")
                    self.findings["hosts"].append(new_host)
                else:
                    # Merge ports
                    existing_ports = existing_host.get("ports", [])
                    for new_port in new_host.get("ports", []):
                        if not any(
                            p.get("id") == new_port.get("id") and p.get("protocol") == new_port.get("protocol")
                            for p in existing_ports
                        ):
                            logging.debug(f"[MERGE] Adding new port {new_port.get('id')}/{new_port.get('protocol')} to host {ip}")
                            existing_ports.append(new_port)
                    existing_host["ports"] = existing_ports
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


    def scan_by_port_service(self, max_workers=None, protocol=None):
        """
        Scan and enumerate services by port and service type.
        Optionally filter by protocol ('tcp' or 'udp').
        
        Args:
            max_workers (int, optional): Maximum number of worker threads.
            protocol (str, optional): Protocol to filter by ('tcp' or 'udp').
        
        Returns:
            dict: Combined findings from all port-specific scans.
        """
        logging.info("[+] Starting port-specific enumeration")
        
        # Define a map of service names to their enum prefixes
        service_prefix_map = {
            re.compile(r"^ftp$")            : "enum_ftp",
            re.compile(r"^http.*")          : "enum_http",
            re.compile(r"^(smb|netbios)")   : "enum_smb",
            re.compile(r"^ssh$")            : "enum_ssh",
            re.compile(r"^(rpc|msrpc)")     : "enum_rpc",
            re.compile(r"^(dns|domain)$")   : "enum_dns",
            re.compile(r"^ldap$")           : "enum_ldap",
            re.compile(r"^snmp$")           : "enum_snmp",
            re.compile(r".*")               : "enum_generic",
        }
        
        brute_prefix_map = {
            re.compile(r"^ssh$")   : "brute_ssh",
            re.compile(r"^ftp$")   : "brute_ftp",
            re.compile(r"^mysql$") : "brute_mysql",
            re.compile(r"^smb$")   : "brute_smb",
            re.compile(r"^smtp$")  : "brute_smtp",  # <-- added
            # Add more as needed
        }
        
        # Track services that need to be enumerated
        port_service_pairs = []
        
        # First, find all port:service pairs from the findings
        hosts = self.findings.get("hosts", [])
        logging.debug(f"[*] Service scan used entry data : {hosts}")
        for host in hosts:
            for port in host.get("ports", []):
                # Filter by protocol if specified
                if protocol and port.get("protocol", "").lower() != protocol:
                    continue
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
                        # Attach brute_prefix
                        for brute_pattern, brute_prefix in brute_prefix_map.items():
                            if brute_pattern.search(service_name):
                                port_data["brute_prefix"] = brute_prefix
                                break
                        else:
                            port_data["brute_prefix"] = None

                        port_service_pairs.append(port_data)
                        logging.debug(f"[*] Will scan with prefix {enum_prefix} on {port_data['host']}:{port_data['port_id']} with {enum_prefix}")
                        break
        
        # If no services found, return early
        if not port_service_pairs:
            logging.info(f"[+] No {protocol} services found to enumerate")
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
        
        logging.info(f"[+] Completed all {protocol} port-specific enumeration")
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
        brute_prefix = port_data.get("brute_prefix")
        temp_scanner = Scanner(options)
        all_methods = [
            method for method in dir(temp_scanner)
            if (
                (method.startswith(enum_prefix) or method == "enum_generic_product_search") or
                (brute_prefix and method.startswith(brute_prefix))
            )
            and callable(getattr(temp_scanner, method))
        ]
        if not all_methods:
            logging.warning(
                f"[PLUGIN DISCOVERY] No plugins found for {port_data['service']} on {port_data['host']}:{port_data['port_id']} "
                f"(enum_prefix: {enum_prefix}, brute_prefix: {brute_prefix})"
            )
        filtered_methods = []
        for method in all_methods:
            func = getattr(temp_scanner, method)
            deps = getattr(func, "depends_on", [])
            unsatisfiable = [dep for dep in deps if dep not in all_methods and not dep.startswith("scan_")]
            if not unsatisfiable:
                filtered_methods.append(method)
            else:
                logging.warning(
                    f"[PLUGIN FILTER] Filtering OUT plugin '{method}' for {port_data['host']}:{port_data['port_id']} "
                    f"(unsatisfiable deps: {unsatisfiable}, all deps: {deps}, available: {all_methods})"
                )
        if all_methods and not filtered_methods:
            logging.warning(
                f"[PLUGIN FILTER] All discovered plugins were filtered out for {port_data['service']} on {port_data['host']}:{port_data['port_id']} "
                f"(discovered: {all_methods})"
            )
        if not filtered_methods:
            logging.warning(f"No methods found with prefix {enum_prefix} or enum_generic_product_search")
            return {}

        # --- BRUTEFORCE FILTER ---
        if not options.get("enable_bruteforce", False):
            filtered_methods = [m for m in filtered_methods if not m.startswith("brute_")]

        # Sort so brute_ plugins are last
        filtered_methods.sort(key=lambda m: m.startswith("brute_"))

        if not filtered_methods:
            logging.warning(f"No methods found with prefix {enum_prefix} or enum_generic_product_search")
            return {}

        return self._execute_plugins_with_scheduler(temp_scanner, filtered_methods, max_workers=max_workers)

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
        graph = self._build_plugin_dependency_graph(temp_scanner, methods)
        dependents = {k: set() for k in graph}
        for k, deps in graph.items():
            for dep in deps:
                dependents.setdefault(dep, set()).add(k)
        completed = set()
        results = {}
        plugin_results = {}
        if hasattr(self, "_virtual_scan_plugins"):
            for scan_plugin in self._virtual_scan_plugins:
                plugin_results[scan_plugin] = {"virtual": True}
                completed.add(scan_plugin)
        # --- FIX: ready plugins are those whose deps are all completed ---
        ready = [m for m in methods if all(dep in completed for dep in graph[m])]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or 4) as executor:
            futures = {}
            logging.debug(f"[PLUGIN SCHEDULER] Initial ready plugins: {ready}")
            if not ready:
                logging.warning(
                    f"[PLUGIN SCHEDULER] No plugins ready to run for {temp_scanner.options.get('current_port', {}).get('host')}:{temp_scanner.options.get('current_port', {}).get('port_id')}. "
                    f"Check dependencies and _virtual_scan_plugins."
                )
            while ready or futures:
                for plugin in ready:
                    host_port_info = f"{temp_scanner.options.get('current_port', {}).get('host')}:{temp_scanner.options.get('current_port', {}).get('port_id')}"
                    logging.info(f"[PLUGIN EXEC] Starting {plugin} for {host_port_info}")
                    
                    # Submit the task
                    future = executor.submit(getattr(temp_scanner, plugin), plugin_results)
                    start_time = time.time()
                    futures[future] = (plugin, start_time)
                    
                    # Store the future for later reference
                    # This allows us to access the thread ID when needed
                    # Register plugin with the monitor but don't pass the thread yet
                    # We'll update it after the future is running
                    plugin_monitor.register_plugin(plugin, host_port_info)
                
                ready = []
                for future in concurrent.futures.as_completed(futures):
                    plugin, start_time = futures.pop(future)
                    # Calculate execution time
                    execution_time = time.time() - start_time
                    host_port_info = f"{temp_scanner.options.get('current_port', {}).get('host')}:{temp_scanner.options.get('current_port', {}).get('port_id')}"
                    
                    # Unregister the plugin from monitoring
                    plugin_monitor.unregister_plugin(plugin)
                    
                    try:
                        result = future.result()
                        # Log completion with timing information
                        logging.info(f"[PLUGIN DONE] {plugin} completed for {host_port_info} in {execution_time:.2f} seconds")
                    except Exception as e:
                        logging.error(f"[PLUGIN ERROR] {plugin} failed for {host_port_info} in {execution_time:.2f} seconds: {e}")
                        result = {"skipped": f"Exception: {e}"}
                    
                    results[plugin] = result
                    plugin_results[plugin] = result
                    completed.add(plugin)
                    
                    # If this plugin was skipped, propagate skip to dependents
                    if isinstance(result, dict) and "skipped" in result:
                        for dep in dependents.get(plugin, []):
                            if dep not in completed and dep not in ready:
                                logging.debug(f"[SKIP PROPAGATE] Skipping {dep} because dependency {plugin} was skipped.")
                                plugin_results[dep] = {"skipped": f"Dependency {plugin} was skipped: {result['skipped']}"}
                                completed.add(dep)
                    for dep in dependents.get(plugin, []):
                        if all(d in completed for d in graph[dep]) and dep not in completed and dep not in ready:
                            ready.append(dep)
                    break
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
