# Manages the lifecycle of processing jobs.
import os
import uuid
import json
import tempfile
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field

# The base directory for all jobs, as specified in the process flow.
# %ProgramData% is the common location for application data.
JOB_ROOT_DIR = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "SMX" / "Jobs"

class JobState(Enum):
    """Enumeration of all possible job states."""
    INITIALIZED = "INITIALIZED"
    ENUMERATING = "ENUMERATING"
    POLICY_CHECK = "POLICY_CHECK"
    SCANNING = "SCANNING"
    PACKAGING = "PACKAGING"
    SUCCESS = "SUCCESS"
    FAILED_POLICY = "FAILED_POLICY"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"

@dataclass
class Job:
    """Represents a single processing job."""
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: JobState = JobState.INITIALIZED
    
    @property
    def path(self) -> Path:
        """The directory where the job's data is stored."""
        return JOB_ROOT_DIR / self.job_id

class JobManager:
    """Handles the creation and state management of jobs."""
    def __init__(self):
        # Ensure the root job directory exists.
        JOB_ROOT_DIR.mkdir(parents=True, exist_ok=True)

    def initialize_job(self, device_metadata: dict) -> Job:
        """
        Creates a new job, including its directory structure and initial files.
        
        Args:
            device_metadata: A dictionary of metadata collected from the DeviceManager.
            
        Returns:
            A Job object representing the newly created job.
        """
        job = Job()
        print(f"Initializing job {job.job_id}...")
        
        try:
            # Create the job-specific directory.
            job.path.mkdir(parents=True, exist_ok=False)
            
            # Write initial files.
            self._write_json_atomically(job.path / "metadata.json", device_metadata)
            self.update_state(job, JobState.INITIALIZED)
            
            # Create an empty log file.
            (job.path / "logs.jsonl").touch()
            
            print(f"Job {job.job_id} initialized successfully at {job.path}")
            return job
            
        except FileExistsError:
            print(f"Error: Job directory {job.path} already exists.")
            # This should be extremely rare due to UUID4.
            return None
        except Exception as e:
            print(f"Failed to initialize job {job.job_id}: {e}")
            # Consider cleanup logic here if initialization fails midway.
            return None

    def update_state(self, job: Job, new_state: JobState):
        """
        Atomically updates the state of the job.
        """
        job.state = new_state
        state_payload = {
            "current_state": new_state.value,
            "history": [] # Placeholder for state transition history
        }
        self._write_json_atomically(job.path / "state.json", state_payload)

    def _write_json_atomically(self, file_path: Path, data: dict):
        """
        Writes a dictionary to a JSON file atomically to prevent corruption.
        This is done by writing to a temporary file first, then renaming it.
        """
        fd, tmp_path_str = tempfile.mkstemp(dir=file_path.parent)
        tmp_path = Path(tmp_path_str)
        
        try:
            with os.fdopen(fd, 'w') as tmp_file:
                json.dump(data, tmp_file, indent=4)
            
            # Atomic replace operation (overwrite if exists).
            tmp_path.replace(file_path)
        except Exception as e:
            print(f"Failed to write to {file_path} atomically: {e}")
            # Clean up the temporary file if it still exists
            if tmp_path.exists():
                tmp_path.unlink()
            raise
