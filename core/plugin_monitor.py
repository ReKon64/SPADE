import threading
import time
import logging
import subprocess
from datetime import datetime

class PluginMonitor:
    """
    Monitor active plugins and periodically log their status.
    This helps track long-running plugins and overall scan progress.
    Also handles killing plugins that exceed their maximum runtime.
    """
    
    def __init__(self, interval=30, default_timeout=300):
        """
        Initialize the plugin monitor.
        
        Args:
            interval (int): Interval in seconds between status updates
            default_timeout (int): Default timeout for plugins in seconds (5 minutes)
        """
        self.interval = interval
        self.default_timeout = default_timeout
        self.active_plugins = {}  # {plugin_name: {"start_time": timestamp, "target": "host:port", "cmd": cmd}}
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
    
    def register_plugin(self, plugin_name, target_info, cmd=None, timeout=None):
        """
        Register a plugin as active
        
        Args:
            plugin_name (str): Name of the plugin that started
            target_info (str): Target information (e.g., "host:port")
            cmd (str, optional): Command being executed by the plugin
            timeout (int, optional): Maximum runtime in seconds before killing
        """
        with self.lock:
            self.active_plugins[plugin_name] = {
                "start_time": time.time(),
                "target": target_info,
                "cmd": cmd,
                "timeout": timeout or self.default_timeout
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
        """Main monitoring loop that periodically logs active plugins and kills timed-out ones"""
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
                if runtime > info["timeout"]:
                    timed_out_plugins.append((plugin_name, info))
        
        # Process timed out plugins outside the lock to avoid deadlocks
        for plugin_name, info in timed_out_plugins:
            logging.warning(f"[PLUGIN TIMEOUT] {plugin_name} timed out after {info['timeout']} seconds on {info['target']}")
            
            # Kill the process if we have a command
            if info["cmd"]:
                try:
                    # Try to find and kill the process
                    target = info["target"].split(":")[0]  # Extract host from "host:port"
                    kill_cmd = f"pkill -f '{info['cmd']}'"
                    subprocess.run(kill_cmd, shell=True, check=False)
                    logging.info(f"[PLUGIN TIMEOUT] Killed process for {plugin_name}")
                except Exception as e:
                    logging.error(f"[PLUGIN TIMEOUT] Error killing process for {plugin_name}: {e}")
            
            # Unregister the plugin
            self.unregister_plugin(plugin_name)

# Global instance
plugin_monitor = PluginMonitor()
