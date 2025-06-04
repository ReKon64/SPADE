import threading
import time
import logging
from datetime import datetime

class PluginMonitor:
    """
    Monitor active plugins and periodically log their status.
    This helps track long-running plugins and overall scan progress.
    """
    
    def __init__(self, interval=30):
        """
        Initialize the plugin monitor.
        
        Args:
            interval (int): Interval in seconds between status updates
        """
        self.interval = interval
        self.active_plugins = {}  # {plugin_name: {"start_time": timestamp, "target": "host:port"}}
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
    
    def register_plugin(self, plugin_name, target_info):
        """
        Register a plugin as active
        
        Args:
            plugin_name (str): Name of the plugin that started
            target_info (str): Target information (e.g., "host:port")
        """
        with self.lock:
            self.active_plugins[plugin_name] = {
                "start_time": time.time(),
                "target": target_info
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
        """Main monitoring loop that periodically logs active plugins"""
        while self.running:
            time.sleep(self.interval)
            self._log_active_plugins()
    
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

# Global instance
plugin_monitor = PluginMonitor()
