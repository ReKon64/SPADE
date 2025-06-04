from core.imports import *

VERBOSE_LEVEL_NUM = 15
logging.addLevelName(VERBOSE_LEVEL_NUM, "REAL-TIME") 
def realtime(self, message, *args, **kws):
    if self.isEnabledFor(VERBOSE_LEVEL_NUM):
        self._log(VERBOSE_LEVEL_NUM, message, args, **kws)
logging.Logger.realtime = realtime


class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "prefix") or not record.prefix:
            record.prefix = ""
        return super().format(record)

class MemoryUsageFormatter(logging.Formatter):
    def format(self, record):
        process = psutil.Process(os.getpid())
        memory_usage = process.memory_info().rss / 1024 / 1024
        record.memory_usage = f"{memory_usage:.2f} MB"
        if not hasattr(record, "prefix") or not record.prefix:
            record.prefix = ""
        return super().format(record)

def run_and_log(cmd, very_verbose=False, prefix=None, timeout=None):
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
            prefix = f"[{host}:{port}] - [{prefix}]"
        elif host:
            prefix = f"[{host}] - [{prefix}]"
        elif port:
            prefix = f"[{port}] - [{prefix}]"
        else:
            prefix = f"[{prefix}]"
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    output = ""
    
    # Timer for timeout handling
    timer = None
    if timeout:
        def kill_process():
            if process.poll() is None:  # Process is still running
                logging.warning(f"Command '{cmd}' timed out after {timeout}s. Terminating.")
                process.terminate()
                time.sleep(1)
                if process.poll() is None:  # Process still didn't terminate
                    process.kill()
                    logging.warning(f"Force killed process for command '{cmd}'")
        
        timer = threading.Timer(timeout, kill_process)
        timer.daemon = True
        timer.start()
    
    try:
        for line in process.stdout:
            output += line
            if very_verbose:
                logger.realtime(f"{prefix} {line.rstrip()}")

        return_code = process.wait()
        
        if return_code != 0 and not very_verbose:
            logging.error(f"Command '{cmd}' exited with return code {return_code}")
            
        return output
    finally:
        if timer:
            timer.cancel()