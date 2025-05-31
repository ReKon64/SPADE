from core.imports import *

VERBOSE_LEVEL_NUM = 15
logging.addLevelName(VERBOSE_LEVEL_NUM, "REAL-TIME") 
def realtime(self, message, *args, **kws):
    if self.isEnabledFor(VERBOSE_LEVEL_NUM):
        self._log(VERBOSE_LEVEL_NUM, message, args, **kws)
logging.Logger.realtime = realtime


class MemoryUsageFormatter(logging.Formatter):
    def format(self, record):
        # Get the current process
        process = psutil.Process(os.getpid())
        
        # Get memory info in MB
        memory_usage = process.memory_info().rss / 1024 / 1024
        
        # Add memory usage as a field to the record
        record.memory_usage = f"{memory_usage:.2f} MB"
        if not hasattr(record, "prefix"):
            record.prefix = ""
        if not hasattr(record, "hostport"):
            record.hostport = ""
        # Call the original formatter
        return super().format(record)

class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "prefix"):
            record.prefix = ""
        if not hasattr(record, "hostport"):
            record.hostport = ""
        return super().format(record)

class ContextPrefixFilter(logging.Filter):
    def filter(self, record):
        frame = inspect.currentframe()
        while frame:
            f_locals = frame.f_locals
            host = f_locals.get("host")
            port = f_locals.get("port") or f_locals.get("port_id")
            func = frame.f_code.co_name
            # Set hostport and prefix separately
            if host and port:
                record.hostport = f"{host}:{port}"
            elif host:
                record.hostport = f"{host}"
            elif port:
                record.hostport = f"{port}"
            else:
                record.hostport = ""
            record.prefix = f"[{func.upper()}]"
            break
            frame = frame.f_back
        else:
            record.hostport = ""
            record.prefix = ""
        return True
    

def run_and_log(cmd, very_verbose=False, prefix=None):
    """
    Run a shell command, streaming output in real time if very_verbose is enabled.
    Returns the full output as a string.
    """
    logger = logging.getLogger()
    # Automatically set prefix to caller's function name in uppercase if not provided
    if prefix is None:
        frame = inspect.currentframe()
        caller_frame = frame.f_back
        prefix = caller_frame.f_code.co_name.upper()
        # Try to extract host and port/port_id from caller's locals
        host = caller_frame.f_locals.get("host")
        port = caller_frame.f_locals.get("port") or caller_frame.f_locals.get("port_id")
        if host and port:
            prefix = f"{prefix} {host}:{port}"
        elif host:
            prefix = f"{prefix} {host}"
        elif port:
            prefix = f"{prefix} {port}"
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    output = ""
    for line in process.stdout:
        output += line
        if very_verbose:
            logger.realtime(f"[{prefix}] {line.rstrip()}")
    process.wait()
    return output