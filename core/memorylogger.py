from imports import *

class MemoryUsageFormatter(logging.Formatter):
    def format(self, record):
        # Get the current process
        process = psutil.Process(os.getpid())
        
        # Get memory info in MB
        memory_usage = process.memory_info().rss / 1024 / 1024
        
        # Add memory usage as a field to the record
        record.memory_usage = f"{memory_usage:.2f} MB"
        
        # Call the original formatter
        return super().format(record)