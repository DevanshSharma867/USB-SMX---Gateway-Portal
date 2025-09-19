# Handles file enumeration, sanitization, and malware scanning.
import os
import ctypes
import subprocess
from enum import Enum
from ctypes import wintypes
from pathlib import Path
from .job_manager import Job, JobState
from .crypto import CryptoManager

# Constants and structures for Windows API calls
INVALID_HANDLE_VALUE = -1

class ScanVerdict(Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"

class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [("StreamSize", wintypes.LARGE_INTEGER),
                ("cStreamName", wintypes.WCHAR * 296)] # STREAM_NAME_SIZE_STRING

class FileProcessor:
    """Processes files on the USB device."""
    def __init__(self, job_manager):
        self._job_manager = job_manager
        self._mp_cmd_run_path = self._find_mp_cmd_run()

    def _find_mp_cmd_run(self) -> str | None:
        """
        Finds the full path to MpCmdRun.exe.
        Searches common locations for Windows Defender.
        """
        print("Searching for MpCmdRun.exe...")
        # Common paths for the executable
        possible_paths = [
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Windows Defender" / "MpCmdRun.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Windows Defender" / "MpCmdRun.exe",
        ]
        
        # Also check the platform-specific directory which is more common now
        platform_dir = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
        if platform_dir.exists():
            # Get the latest version directory, e.g., "4.18.2205.7-0"
            version_dirs = sorted([d for d in platform_dir.iterdir() if d.is_dir()], reverse=True)
            if version_dirs:
                possible_paths.append(version_dirs[0] / "MpCmdRun.exe")

        for path in possible_paths:
            if path.exists():
                print(f"Found MpCmdRun.exe at: {path}")
                return str(path)
        
        print("MpCmdRun.exe could not be found in standard locations.")
        return None

    def enumerate_files(self, job: Job, root_path: str) -> list[Path]:
        """
        Enumerates all files, detects ADS, scans for malware, and returns a sorted list.
        """
        print(f"Starting file enumeration for job {job.job_id} on {root_path}")
        self._job_manager.update_state(job, JobState.ENUMERATING)
        
        all_files = []
        root = Path(root_path)
        self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        try:
            for dirpath, _, filenames in os.walk(root):
                for filename in filenames:
                    if job.state == JobState.QUARANTINED:
                        print("Malware detected, aborting file enumeration.")
                        return [] # Stop processing immediately

                    full_path = Path(dirpath) / filename
                    
                    if self._is_path_safe(full_path, root):
                        all_files.append(full_path)
                        
                        # ADS Check
                        streams = self._get_alternate_data_streams(full_path)
                        non_whitelisted_streams = [s for s in streams if s not in [':$DATA', ':Zone.Identifier:$DATA']]
                        if non_whitelisted_streams:
                            print(f"[!] Found non-whitelisted ADS in {full_path}: {non_whitelisted_streams}")

                        # Malware Scan
                        verdict, details = self.scan_file(full_path)
                        print(f"Scan result for {full_path}: {verdict.name} - {details}")
                        if verdict == ScanVerdict.INFECTED:
                            print(f"[!!!] MALWARE DETECTED in {full_path}! Threat: {details}")
                            self._job_manager.update_state(job, JobState.QUARANTINED)
                            # The loop will terminate on the next iteration
                    else:
                        print(f"[!] Unsafe path detected and skipped: {full_path}")

            if job.state != JobState.QUARANTINED:
                self._job_manager.update_state(job, JobState.SCANNING) # Or next state
            
            all_files.sort()
            print(f"Enumerated {len(all_files)} files.")
            return all_files

        except Exception as e:
            print(f"An error occurred during file enumeration: {e}")
            self._job_manager.update_state(job, JobState.FAILED)
            return []

    def package_job(self, job: Job, file_list: list[Path]):
        """
        Encrypts all files and creates the final signed manifest.
        """
        print(f"Starting packaging for job {job.job_id}")
        self._job_manager.update_state(job, JobState.PACKAGING)
        
        crypto_manager = CryptoManager()
        cek = crypto_manager.generate_cek()
        
        # Create a directory for the encrypted data blobs
        data_dir = job.path / "data"
        data_dir.mkdir()
        
        file_manifest_data = {}

        for file_path in file_list:
            print(f"Encrypting {file_path}...")
            encrypted_data = crypto_manager.encrypt_file(file_path, cek)
            if not encrypted_data:
                print(f"[!] Failed to encrypt {file_path}. Aborting job.")
                self._job_manager.update_state(job, JobState.FAILED)
                return

            ciphertext, nonce, tag = encrypted_data
            
            # Use the hash of the original file path to create a unique, sanitized filename
            # This avoids issues with long paths or special characters in the job directory.
            file_hash = crypto_manager.get_sha256_hash(str(file_path).encode('utf-8'))
            encrypted_file_path = data_dir / file_hash
            
            with open(encrypted_file_path, 'wb') as f:
                f.write(ciphertext)

            file_manifest_data[str(file_path)] = {
                "encrypted_blob_path": str(encrypted_file_path.name),
                "sha256_encrypted": crypto_manager.get_sha256_hash(ciphertext),
                "nonce": nonce.hex(),
                "tag": tag.hex()
            }

        # Create and sign the manifest
        manifest = crypto_manager.create_manifest(job, file_manifest_data)
        signed_manifest = crypto_manager.sign_manifest_with_vault(manifest)
        
        # Write the final manifest to the job directory
        self._job_manager.update_state(job, JobState.SUCCESS, {"manifest": signed_manifest})
        
        print(f"Job {job.job_id} completed successfully!")

    def scan_file(self, file_path: Path) -> tuple[ScanVerdict, str]:
        """
        Scans a file with Microsoft Defender and ClamAV.
        Returns a verdict and a details string.
        """
        # 1. Microsoft Defender Scan
        if self._mp_cmd_run_path:
            try:
                # Using -ScanType 3 for custom scan on a single file.
                # -DisableRemediation keeps Defender from automatically deleting the file.
                result = subprocess.run(
                    [self._mp_cmd_run_path, "-Scan", "-ScanType", "3", "-File", str(file_path), "-DisableRemediation"],
                    capture_output=True, text=True, timeout=120, check=True
                )
                if "Threats found: 0" in result.stdout:
                    pass # Clean, proceed to next scanner
                else:
                    # Extract threat name
                    threat_name = "Unknown"
                    for line in result.stdout.splitlines():
                        if "Threat " in line:
                            threat_name = line.split("Threat ")[1].strip()
                            break
                    return (ScanVerdict.INFECTED, f"Defender: {threat_name}")
            except subprocess.TimeoutExpired:
                return (ScanVerdict.TIMEOUT, "Defender scan timed out.")
            except subprocess.CalledProcessError as e:
                # MpCmdRun exits with a non-zero code even when threats are found.
                # We need to parse the output to be sure.
                if "Threats found: 0" not in e.stdout:
                     return (ScanVerdict.INFECTED, f"Defender: Threat detected (parsing output)")
                print(f"Defender scan error for {file_path}: {e.stderr}")
                # Don't return ERROR yet, let ClamAV try.
        else:
            print("MpCmdRun.exe path not found. Skipping Defender scan.")
        
        # 2. ClamAV Scan (if Defender found nothing)
        try:
            result = subprocess.run(
                ["clamscan.exe", "--no-summary", str(file_path)],
                capture_output=True, text=True, timeout=120, check=True
            )
            if result.stdout.strip().endswith("OK"):
                return (ScanVerdict.CLEAN, "Clean")
            else:
                threat_name = result.stdout.strip().split(": ")[1]
                return (ScanVerdict.INFECTED, f"ClamAV: {threat_name}")
        except FileNotFoundError:
            print("clamscan.exe not found. Skipping ClamAV scan.")
            return (ScanVerdict.CLEAN, "Scanners not found") # Default to clean if no scanners are available
        except subprocess.TimeoutExpired:
            return (ScanVerdict.TIMEOUT, "ClamAV scan timed out.")
        except subprocess.CalledProcessError as e:
            # Clamscan exits 1 if a virus is found.
            if e.returncode == 1:
                threat_name = e.stdout.strip().split(": ")[1]
                return (ScanVerdict.INFECTED, f"ClamAV: {threat_name}")
            else:
                print(f"ClamAV scan error for {file_path}: {e.stderr}")
                return (ScanVerdict.ERROR, f"ClamAV error (code {e.returncode})")

        return (ScanVerdict.CLEAN, "Clean")

    def _get_alternate_data_streams(self, file_path: Path) -> list[str]:
        """
        Uses the Windows API to find all data streams for a file.
        Returns a list of stream names (e.g., [':$DATA', ':Zone.Identifier:$DATA']).
        """
        stream_data = WIN32_FIND_STREAM_DATA()
        streams = []
        
        find_handle = self._kernel32.FindFirstStreamW(
            ctypes.c_wchar_p(str(file_path)),
            0, # InfoLevel: FindStreamInfoStandard
            ctypes.byref(stream_data),
            0 # dwFlags
        )

        if find_handle == INVALID_HANDLE_VALUE:
            return []

        try:
            while True:
                streams.append(stream_data.cStreamName)
                
                if not self._kernel32.FindNextStreamW(find_handle, ctypes.byref(stream_data)):
                    break
        finally:
            self._kernel32.FindClose(find_handle)
            
        # The stream name is in the format :<name>:$<type>
        # We return the full name for accurate identification.
        return [s for s in streams if s]

    def _is_path_safe(self, path: Path, root: Path) -> bool:
        """
        Validates that the path is safe and does not attempt traversal.
        It ensures the resolved path is still within the root directory.
        """
        try:
            # Resolving the path will handle ".." traversal.
            # Path.is_relative_to() is available in Python 3.9+
            # For broader compatibility, we check if the root is a parent.
            return root in path.resolve().parents or root == path.resolve().parent
        except Exception:
            # Path resolution can fail for various reasons (e.g., invalid characters)
            return False