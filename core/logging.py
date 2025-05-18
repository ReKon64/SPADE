from imports import *

VERBOSE_LEVEL_NUM = 15
logging.addLevelName(VERBOSE_LEVEL_NUM, "VERBOSE")

def verbose(self, message, *args, **kws):
    if self.isEnabledFor(VERBOSE_LEVEL_NUM):
        self._log(VERBOSE_LEVEL_NUM, message, args, **kws)
logging.Logger.verbose = verbose


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
    
def run_and_log(cmd, very_verbose=False):
    """
    Run a shell command, streaming output in real time if very_verbose is enabled.
    Returns the full output as a string.
    """
    logger = logging.getLogger()
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    output = ""
    for line in process.stdout:
        output += line
        if very_verbose:
            logger.verbose(line.rstrip())
    process.wait()
    return output