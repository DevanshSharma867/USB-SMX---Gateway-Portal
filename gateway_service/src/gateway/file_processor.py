# Handles file enumeration, policy checks, scanning, and packaging.
import os
import json
import subprocess
from enum import Enum
from pathlib import Path
from .job_manager import Job, JobState, JobManager
from .crypto import CryptoManager

class ScanVerdict(Enum):
    """Enumeration of possible scan results."""
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"

# MVP Policy: A simple blacklist of file extensions that are not allowed.
POLICY_BLACKLIST_EXTENSIONS = {".exe", ".dll", ".bat", ".sh"}

# MVP Threat: A simple filename to simulate a malware detection.
THREAT_FILENAME = "eicar.com"

class FileProcessor:
    """Processes files on a device according to the defined workflow."""
    def __init__(self, job_manager: JobManager):
        self._job_manager = job_manager
        self._crypto_manager = CryptoManager()
        self._policies = self._load_policies()
        # Initialize Windows API for ADS detection
        try:
            import ctypes
            self._kernel32 = ctypes.windll.kernel32
        except (ImportError, AttributeError):
            self._kernel32 = None

    def _load_policies(self) -> list[dict]:
        """Loads and validates policies from the policy.json file."""
        try:
            policy_path = Path(__file__).parent / "policy.json"
            with open(policy_path, 'r') as f:
                policy_data = json.load(f)
            
            # Basic validation
            if 'policies' not in policy_data or not isinstance(policy_data['policies'], list):
                print("Warning: policy.json is malformed. No policies will be applied.")
                return []

            # Filter for enabled policies only
            enabled_policies = [p for p in policy_data['policies'] if p.get('enabled', False)]
            print(f"Loaded {len(enabled_policies)} enabled policies.")
            return enabled_policies
        except FileNotFoundError:
            print("Warning: policy.json not found. No policies will be applied.")
            return []
        except Exception as e:
            print(f"Warning: Failed to load or parse policy.json: {e}")
            return []

    def process_device(self, job: Job, root_path: str):
        """
        Orchestrates the entire file processing pipeline for a given job and device.
        """
        try:
            # 1. File Enumeration
            self._job_manager.update_state(job, JobState.ENUMERATING)
            all_files = self._enumerate_files(job, root_path)
            if all_files is None: return # Enumeration failed

            # 2. Policy Enforcement
            self._job_manager.update_state(job, JobState.POLICY_CHECK)
            if not self._enforce_policies(job, all_files):
                return # Policy violation detected

            # 3. Malware Scanning
            self._job_manager.update_state(job, JobState.SCANNING)
            if not self._scan_files(job, all_files):
                return # Threat detected

            # 4. Cryptographic Packaging
            self._job_manager.update_state(job, JobState.PACKAGING)
            self._package_job(job, all_files)

            # 5. Finalize Job
            self._job_manager.update_state(job, JobState.SUCCESS, {"detail": f"Job completed successfully. {len(all_files)} files processed."})
            print(f"Job {job.job_id} completed successfully!")

        except Exception as e:
            print(f"An unhandled error occurred during job {job.job_id}: {e}")
            self._job_manager.update_state(job, JobState.FAILED, {"error": str(e)})

    def _enumerate_files(self, job: Job, root_path: str) -> list[Path] | None:
        """Enumerates all files from the root path, returning a sorted list."""
        self._job_manager.log_event(job, "ENUMERATION_START", {"root_path": root_path})
        all_files = []
        try:
            for dirpath, _, filenames in os.walk(root_path):
                for filename in filenames:
                    full_path = Path(dirpath) / filename
                    all_files.append(full_path)
            
            all_files.sort()
            self._job_manager.log_event(job, "ENUMERATION_COMPLETE", {"file_count": len(all_files)})
            return all_files
        except Exception as e:
            self._job_manager.update_state(job, JobState.FAILED, {"error": f"File enumeration failed: {e}"})
            return None

    def enumerate_files(self, job: Job, root_path: str) -> list[Path] | None:
        """Public method for file enumeration (used by tests)."""
        return self._enumerate_files(job, root_path)

    def _enforce_policies(self, job: Job, file_list: list[Path]) -> bool:
        """Checks files against defined policies. Returns False if a violation occurs."""
        self._job_manager.log_event(job, "POLICY_CHECK_START", {"policy_count": len(self._policies)})
        
        # A map of policy types to their handler methods
        policy_handlers = {
            "fileExtensionBlacklist": self._policy_file_extension_blacklist,
            "maxFileSize": self._policy_max_file_size
        }

        for policy in self._policies:
            handler = policy_handlers.get(policy['type'])
            if not handler:
                self._job_manager.log_event(job, "POLICY_EVAL_WARN", {"policy_id": policy.get('id'), "reason": "No handler found for policy type."})
                continue

            self._job_manager.log_event(job, "POLICY_EVAL_START", {"policy_id": policy.get('id'), "policy_name": policy.get('name')})
            if not handler(job, file_list, policy):
                # The handler is responsible for setting the job state and logging the specific failure
                return False

        return True

    def _policy_file_extension_blacklist(self, job: Job, file_list: list[Path], policy: dict) -> bool:
        """Handler for the fileExtensionBlacklist policy."""
        blacklisted_extensions = set(policy.get('parameters', {}).get('extensions', []))
        if not blacklisted_extensions:
            return True # Nothing to check

        for file_path in file_list:
            if file_path.suffix.lower() in blacklisted_extensions:
                details = {
                    "policy_id": policy.get('id'),
                    "file_path": str(file_path),
                    "reason": f"File extension '{file_path.suffix}' is blacklisted."
                }
                self._job_manager.update_state(job, JobState.FAILED_POLICY, details)
                return False
        return True

    def _policy_max_file_size(self, job: Job, file_list: list[Path], policy: dict) -> bool:
        """Handler for the maxFileSize policy."""
        max_size_mb = policy.get('parameters', {}).get('max_size_mb')
        if not max_size_mb:
            return True # Nothing to check
        
        max_size_bytes = max_size_mb * 1024 * 1024

        for file_path in file_list:
            try:
                file_size = os.path.getsize(file_path)
                if file_size > max_size_bytes:
                    details = {
                        "policy_id": policy.get('id'),
                        "file_path": str(file_path),
                        "file_size_mb": round(file_size / (1024*1024), 2),
                        "reason": f"File size ({round(file_size / (1024*1024), 2)} MB) exceeds the limit of {max_size_mb} MB."
                    }
                    self._job_manager.update_state(job, JobState.FAILED_POLICY, details)
                    return False
            except OSError as e:
                # Could fail if the file is deleted during processing, etc.
                self._job_manager.log_event(job, "POLICY_EVAL_WARN", {"policy_id": policy.get('id'), "reason": f"Could not get size of file {file_path}: {e}"})
        return True

    def _scan_files(self, job: Job, file_list: list[Path]) -> bool:
        """(MVP) Simulates scanning files for threats. Returns False if a threat is found."""
        self._job_manager.log_event(job, "SCANNING_START", {"scanner": "MVP_SIMULATED_SCANNER"})
        for file_path in file_list:
            if file_path.name.lower() == THREAT_FILENAME:
                details = {
                    "file_path": str(file_path),
                    "threat_name": "SIMULATED_EICAR_TEST_FILE"
                }
                self._job_manager.update_state(job, JobState.QUARANTINED, details)
                return False
        return True

    def _package_job(self, job: Job, file_list: list[Path]):
        """Encrypts files and creates the final manifest."""
        self._job_manager.log_event(job, "PACKAGING_START", {"algorithm": "AES-256-GCM"})
        
        cek = self._crypto_manager.generate_cek()
        self._crypto_manager.save_cek_to_disk(cek, job.path / "cek.key") # Insecure, for MVP only

        data_dir = job.path / "data"
        data_dir.mkdir()
        
        file_manifest_data = {}

        for file_path in file_list:
            encrypted_data = self._crypto_manager.encrypt_file(file_path, cek)
            if not encrypted_data:
                raise RuntimeError(f"Failed to encrypt {file_path}")

            ciphertext, nonce, tag = encrypted_data
            
            file_hash = self._crypto_manager.get_sha256_hash(str(file_path).encode('utf-8'))
            encrypted_file_path = data_dir / file_hash
            
            with open(encrypted_file_path, 'wb') as f:
                f.write(ciphertext)

            file_manifest_data[str(file_path)] = {
                "encrypted_blob_name": file_hash,
                "sha256_encrypted": self._crypto_manager.get_sha256_hash(ciphertext),
                "nonce": nonce.hex(),
                "tag": tag.hex()
            }

        # Create the final manifest
        manifest = {
            "job_id": job.job_id,
            "file_count": len(file_list),
            "encryption_algorithm": "AES-256-GCM",
            "files": file_manifest_data
        }
        self._write_json(job.path / "manifest.json", manifest)
        self._job_manager.log_event(job, "PACKAGING_COMPLETE", {"manifest_path": "manifest.json"})

    def package_job(self, job: Job, file_list: list[Path]):
        """Public method for job packaging (used by tests)."""
        return self._package_job(job, file_list)

    def _write_json(self, file_path: Path, data: dict):
        """Writes a dictionary to a JSON file."""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

    def scan_file(self, file_path: Path) -> tuple[ScanVerdict, str]:
        """
        Scans a single file for malware using available scanners.
        Returns (verdict, details) tuple.
        """
        # Try Microsoft Defender first
        try:
            defender_path = self._find_mp_cmd_run()
            if defender_path:
                result = subprocess.run([
                    defender_path, '-Scan', '-ScanType', '3', '-File', str(file_path)
                ], capture_output=True, text=True, timeout=120)
                
                if "Threat found:" in result.stdout or "Threats found:" in result.stdout:
                    return ScanVerdict.INFECTED, f"Defender: {result.stdout.strip()}"
                elif result.returncode == 0:
                    return ScanVerdict.CLEAN, f"Defender: {result.stdout.strip()}"
                else:
                    # Check if it's actually clean despite error code
                    if "Threats found: 0" in result.stdout:
                        return ScanVerdict.CLEAN, f"Defender: {result.stdout.strip()}"
                    elif "Threats found:" in result.stdout and "Threats found: 0" not in result.stdout:
                        return ScanVerdict.INFECTED, f"Defender: {result.stdout.strip()}"
                    else:
                        return ScanVerdict.ERROR, f"Defender error: {result.stderr.strip()}"
        except FileNotFoundError:
            # Defender not found, try ClamAV
            pass
        except subprocess.TimeoutExpired:
            return ScanVerdict.TIMEOUT, "Defender scan timed out"
        except subprocess.CalledProcessError as e:
            if "Threats found: 0" in e.stdout:
                return ScanVerdict.CLEAN, f"Defender: {e.stdout}"
            elif "Threats found:" in e.stdout and "Threats found: 0" not in e.stdout:
                return ScanVerdict.INFECTED, f"Defender: {e.stdout}"
            else:
                return ScanVerdict.ERROR, f"Defender error (code {e.returncode}): {e.stderr}"
        except Exception as e:
            return ScanVerdict.ERROR, f"Defender error: {str(e)}"
        
        # Try ClamAV as fallback
        try:
            result = subprocess.run([
                'clamscan', '--no-summary', str(file_path)
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 1:  # Virus found
                return ScanVerdict.INFECTED, f"ClamAV: {result.stdout.strip()}"
            elif result.returncode == 0:  # Clean
                return ScanVerdict.CLEAN, f"ClamAV: {result.stdout.strip()}"
            else:
                return ScanVerdict.ERROR, f"ClamAV error (code {result.returncode}): {result.stderr.strip()}"
        except FileNotFoundError:
            return ScanVerdict.CLEAN, "Scanners not found"
        except subprocess.TimeoutExpired:
            return ScanVerdict.TIMEOUT, "ClamAV scan timed out"
        except Exception as e:
            return ScanVerdict.ERROR, f"ClamAV error: {str(e)}"

    def _find_mp_cmd_run(self) -> str | None:
        """Finds the path to MpCmdRun.exe."""
        # Common locations for MpCmdRun.exe
        possible_paths = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
        ]
        
        # Check if any of the common paths exist
        for path in possible_paths:
            if Path(path).exists():
                return path
        
        # Try to find in platform directory
        try:
            platform_dir = Path(r"C:\Program Files\Windows Defender\Platform")
            if platform_dir.exists():
                for version_dir in platform_dir.iterdir():
                    if version_dir.is_dir():
                        mp_cmd_run = version_dir / "MpCmdRun.exe"
                        if mp_cmd_run.exists():
                            return str(mp_cmd_run)
        except Exception:
            pass
        
        return None

    def _is_path_safe(self, path: Path, root: Path) -> bool:
        """Checks if a path is safe (within root directory, no traversal attacks)."""
        try:
            # Check for null bytes and other invalid characters
            path_str = str(path)
            if '\x00' in path_str or len(path_str) > 260:
                return False
            
            # Check for path traversal patterns
            if '..' in path_str or path_str.startswith('/') or '\\' in path_str:
                # More sophisticated check needed
                try:
                    resolved_path = path.resolve()
                    resolved_root = root.resolve()
                    
                    # Check if the resolved path is within the root directory
                    return str(resolved_path).startswith(str(resolved_root))
                except (OSError, ValueError):
                    return False
            
            # Resolve the path to handle any symbolic links or relative components
            resolved_path = path.resolve()
            resolved_root = root.resolve()
            
            # Check if the resolved path is within the root directory
            return str(resolved_path).startswith(str(resolved_root))
        except (OSError, ValueError):
            # If we can't resolve the path, consider it unsafe
            return False

    def _get_alternate_data_streams(self, file_path: Path) -> list[str]:
        """Gets alternate data streams for a file (Windows-specific)."""
        if self._kernel32 is None:
            return []
            
        try:
            import ctypes
            from ctypes import wintypes
            
            # Windows API constants
            INVALID_HANDLE_VALUE = -1
            FILE_ATTRIBUTE_NORMAL = 0x80
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
            
            # Use the instance variable
            kernel32 = self._kernel32
            
            # Define WIN32_FIND_STREAM_DATA structure
            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                _fields_ = [
                    ("StreamSize", ctypes.c_ulonglong),
                    ("cStreamName", ctypes.c_wchar * 260)
                ]
            
            streams = []
            
            # Find first stream
            find_handle = kernel32.FindFirstStreamW(
                str(file_path),
                0,  # FindStreamInfoStandard
                ctypes.byref(WIN32_FIND_STREAM_DATA()),
                0
            )
            
            if find_handle == INVALID_HANDLE_VALUE:
                return streams
            
            try:
                while True:
                    stream_data = WIN32_FIND_STREAM_DATA()
                    if kernel32.FindNextStreamW(find_handle, ctypes.byref(stream_data)):
                        stream_name = stream_data.cStreamName
                        if stream_name and stream_name != "::$DATA":
                            streams.append(stream_name)
                    else:
                        break
            finally:
                kernel32.FindClose(find_handle)
            
            return streams
        except Exception:
            # If we can't enumerate streams, return empty list
            return []
