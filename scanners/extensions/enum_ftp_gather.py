from core.imports import *
from scanners.scanner import Scanner
import ftplib
import os

@Scanner.extend
def enum_ftp_gather(self):
    """
    Attempts anonymous FTP login, recursively lists all files/dirs, and downloads all files to a temp dir in /tmp.
    Returns:
        dict: { "cmd": [actions], "results": { ... } }
    """
    host = self.options["current_port"]["host"]
    port = int(self.options["current_port"]["port_id"])
    # Create a unique temp directory in /tmp for this session
    output_dir = tempfile.mkdtemp(prefix="ftp_", dir="/tmp")
    cmds = []
    results = {"success": False, "files_downloaded": [], "errors": [], "output_dir": output_dir}

    def ftp_recursive_list(ftp, path, file_list):
        try:
            orig_cwd = ftp.pwd()
            ftp.cwd(path)
            items = ftp.nlst()
            for item in items:
                try:
                    ftp.cwd(item)
                    # It's a directory
                    ftp_recursive_list(ftp, item, file_list)
                    ftp.cwd("..")
                except Exception:
                    # It's a file
                    file_list.append(os.path.join(ftp.pwd(), item))
            ftp.cwd(orig_cwd)
        except Exception as e:
            results["errors"].append(f"Error listing {path}: {e}")

    try:
        ftp = ftplib.FTP()
        cmds.append(f"ftp.connect({host}, {port})")
        ftp.connect(host, port, timeout=10)
        cmds.append(f"ftp.login('anonymous', 'anonymous@')")
        ftp.login('anonymous', 'anonymous@')
        results["success"] = True

        # Recursively list all files
        file_list = []
        ftp_recursive_list(ftp, ".", file_list)
        results["all_files"] = file_list

        # Download each file
        for ftp_path in file_list:
            local_path = os.path.join(output_dir, os.path.basename(ftp_path))
            cmds.append(f"ftp.retrbinary('RETR {ftp_path}', open('{local_path}', 'wb').write)")
            try:
                with open(local_path, "wb") as f:
                    ftp.retrbinary(f"RETR {ftp_path}", f.write)
                results["files_downloaded"].append(local_path)
            except Exception as e:
                results["errors"].append(f"Failed to download {ftp_path}: {e}")

        ftp.quit()
    except Exception as e:
        results["errors"].append(f"FTP connection or login failed: {e}")

    return {"cmd": cmds, "results": results}