import threading
import time
import logging
import subprocess
import os
import signal
import psutil
from datetime import datetime
import ctypes

class PluginMonitor:
    """
    Monitor active plugins and periodically log their status.
    This helps track long-running plugins and overall scan progress.
    Also handles killing plugins that exceed their maximum runtime.
    """
    
    def __init__(self, interval=30, default_timeout=180):
        """
        Initialize the plugin monitor.
        
        Args:
            interval (int): Interval in seconds between status updates
            default_timeout (int): Default timeout in seconds (3 minutes)
        """
        self.interval = interval
        self.default_timeout = default_timeout
        self.active_plugins = {}  # {plugin_name: {"start_time": timestamp, "target": "host:port", "thread": thread}}
        self.lock = threading.Lock()
        self.monitor_thread = None
        self.running = False
    
    def start_monitoring(self):
        """Start the monitoring thread"""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
            logging.debug("[PLUGIN MONITOR] Started plugin monitoring thread")
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            logging.debug("[PLUGIN MONITOR] Stopped plugin monitoring thread")
            
        # Force terminate any remaining plugin threads
        with self.lock:
            for plugin_name, info in list(self.active_plugins.items()):
                if info.get("thread") and info.get("thread").is_alive():
                    self._terminate_thread(plugin_name, info.get("thread"))
    
    def register_plugin(self, plugin_name, target_info, thread=None):
        """
        Register a plugin as active
        
        Args:
            plugin_name (str): Name of the plugin that started
            target_info (str): Target information (e.g., "host:port")
            thread (Thread, optional): Thread executing the plugin
        """
        with self.lock:
            self.active_plugins[plugin_name] = {
                "start_time": time.time(),
                "target": target_info,
                "thread": thread or threading.current_thread()
            }
    
    def unregister_plugin(self, plugin_name):
        """
        Unregister a plugin (mark as completed)
        
        Args:
            plugin_name (str): Name of the plugin that completed
        """
        with self.lock:
            if plugin_name in self.active_plugins:
                del self.active_plugins[plugin_name]
    
    def _monitoring_loop(self):
        """Main monitoring loop that periodically logs active plugins and checks for timeouts"""
        while self.running:
            time.sleep(self.interval)
            self._log_active_plugins()
            self._check_for_timeouts()
    
    def _log_active_plugins(self):
        """Log all currently active plugins with their runtime"""
        with self.lock:
            active_count = len(self.active_plugins)
            if active_count == 0:
                return
            
            now = time.time()
            logging.info(f"[PLUGIN STATUS] {active_count} active plugins:")
            
            # Sort plugins by runtime (longest first)
            sorted_plugins = sorted(
                self.active_plugins.items(),
                key=lambda x: now - x[1]["start_time"],
                reverse=True
            )
            
            for plugin_name, info in sorted_plugins:
                runtime = now - info["start_time"]
                target = info["target"]
                logging.info(f"[PLUGIN STATUS] {plugin_name} running for {runtime:.1f}s on {target}")
    
    def _check_for_timeouts(self):
        """Check for plugins that have exceeded their timeout and kill them"""
        now = time.time()
        timed_out_plugins = []
        
        with self.lock:
            # Find plugins that have timed out
            for plugin_name, info in self.active_plugins.items():
                runtime = now - info["start_time"]
                
                if runtime > self.default_timeout:
                    timed_out_plugins.append((plugin_name, info))
        
        # Process timed out plugins outside the lock to avoid deadlocks
        for plugin_name, info in timed_out_plugins:
            target = info["target"]
            logging.warning(f"[PLUGIN TIMEOUT] {plugin_name} timed out after {self.default_timeout} seconds on {target}")
            
            # Terminate the thread if available
            if info.get("thread") and info.get("thread").is_alive():
                self._terminate_thread(plugin_name, info.get("thread"))
                
            # Find and terminate any child processes associated with this thread/plugin
            self._terminate_child_processes(plugin_name)
            
            # Unregister the plugin
            self.unregister_plugin(plugin_name)
    
    def _terminate_thread(self, plugin_name, thread):
        """
        Attempt to terminate a thread
        
        Args:
            plugin_name (str): Name of the plugin
            thread (Thread): Thread to terminate
        """
        try:
            thread_id = thread.ident
            if thread_id:
                # Log the termination attempt
                logging.warning(f"[PLUGIN TIMEOUT] Terminating thread for {plugin_name} (Thread ID: {thread_id})")
                
                # Try to raise an exception in the thread to terminate it
                res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_long(thread_id),
                    ctypes.py_object(SystemExit)
                )
                if res > 1:
                    # If more than one thread was affected, revert
                    ctypes.pythonapi.PyThreadState_SetAsyncExc(
                        ctypes.c_long(thread_id),
                        ctypes.c_long(0)
                    )
                    logging.error(f"[PLUGIN TIMEOUT] Failed to terminate thread for {plugin_name}")
        except Exception as e:
            logging.error(f"[PLUGIN TIMEOUT] Error terminating thread for {plugin_name}: {e}")
    
    def _terminate_child_processes(self, plugin_name):
        """
        Find and terminate any child processes associated with this thread/plugin
        
        Args:
            plugin_name (str): Name of the plugin
        """
        # First, try to identify any child processes of the current process that were spawned
        # after the plugin was registered (and therefore likely belong to it)
        try:
            current_pid = os.getpid()
            current_process = psutil.Process(current_pid)
            
            # Get children of the current process
            for child in current_process.children(recursive=True):
                # Check if the child was created after the plugin started
                if child.create_time() > self.active_plugins.get(plugin_name, {}).get("start_time", 0):
                    try:
                        # First try to terminate gracefully
                        child.terminate()
                        logging.warning(f"[PLUGIN TIMEOUT] Terminated child process {child.pid} for {plugin_name}")
                        
                        # Wait up to 2 seconds for termination
                        gone, alive = psutil.wait_procs([child], timeout=2)
                        if alive:
                            # Force kill if still running
                            for p in alive:
                                p.kill()
                                logging.warning(f"[PLUGIN TIMEOUT] Force killed process {p.pid} for {plugin_name}")
                    except psutil.NoSuchProcess:
                        # Process already died
                        pass
                    except Exception as e:
                        logging.error(f"[PLUGIN TIMEOUT] Error terminating process for {plugin_name}: {e}")
        except Exception as e:
            logging.error(f"[PLUGIN TIMEOUT] Error identifying child processes for {plugin_name}: {e}")
        
        # As a fallback, use common tool names to find and kill processes
        try:
            # Common command-line tools that might be used by plugins
            tools_mapping = {
                # Map plugin prefixes to common external tools they might use
                "enum_http_ferox": ["feroxbuster"],
                "enum_http_whatweb": ["whatweb"],
                "enum_http_nmap": ["nmap"],
                # Add more as patterns emerge
            }
            
            # Find tools that match the current plugin
            tools_to_kill = []
            for prefix, tools in tools_mapping.items():
                if plugin_name.startswith(prefix):
                    tools_to_kill.extend(tools)
            
            if tools_to_kill:
                target = self.active_plugins.get(plugin_name, {}).get("target", "").split(":")[0]
                if target:
                    for tool in tools_to_kill:
                        try:
                            # Find processes containing both the tool name and target in the command line
                            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                                cmdline = proc.info.get('cmdline', [])
                                if cmdline and any(tool in cmd for cmd in cmdline) and target in ' '.join(cmdline):
                                    # Kill the process
                                    try:
                                        proc_obj = psutil.Process(proc.info['pid'])
                                        proc_obj.terminate()
                                        logging.warning(f"[PLUGIN TIMEOUT] Terminated {tool} process {proc.info['pid']} for {plugin_name}")
                                        
                                        # Wait up to 2 seconds for termination
                                        gone, alive = psutil.wait_procs([proc_obj], timeout=2)
                                        if alive:
                                            # Force kill if still running
                                            for p in alive:
                                                p.kill()
                                                logging.warning(f"[PLUGIN TIMEOUT] Force killed {tool} process {p.pid} for {plugin_name}")
                                    except psutil.NoSuchProcess:
                                        # Process already died
                                        pass
                                    except Exception as e:
                                        logging.error(f"[PLUGIN TIMEOUT] Error terminating {tool} process for {plugin_name}: {e}")
                        except Exception as e:
                            logging.error(f"[PLUGIN TIMEOUT] Error finding {tool} processes for {plugin_name}: {e}")
        except Exception as e:
            logging.error(f"[PLUGIN TIMEOUT] Error in fallback process termination for {plugin_name}: {e}")

# Global instance
plugin_monitor = PluginMonitor()
