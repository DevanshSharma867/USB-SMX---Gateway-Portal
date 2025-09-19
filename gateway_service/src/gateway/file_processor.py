# Handles file enumeration, policy checks, scanning, and packaging.
import os
import json
from pathlib import Path
from .job_manager import Job, JobState, JobManager
from .crypto import CryptoManager

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

    def _write_json(self, file_path: Path, data: dict):
        """Writes a dictionary to a JSON file."""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
