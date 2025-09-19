# Handles USB device detection, metadata collection, and processing.
import threading
import time
import wmi
import pythoncom
import datetime
import socket
from .job_manager import Job, JobState, JobManager
from .file_processor import FileProcessor

class DeviceManager:
    """
    Monitors for USB device insertions and removals, and processes them.
    """
    def __init__(self):
        self._job_manager = JobManager()
        self._file_processor = FileProcessor(self._job_manager)
        self._monitoring_thread = None
        self._stop_event = threading.Event()

    def _collect_metadata(self, wmi_connection, volume_obj):
        """Collects metadata for the specified drive volume object using multiple methods."""
        disk_drive = None
        drive_letter = volume_obj.DriveLetter
        if not drive_letter:
            print("Volume has no drive letter, cannot collect detailed metadata.")
            return None

        try:
            # Method 1: Start from the Volume object
            print("Attempting metadata collection via Volume->Partition association...")
            partitions = volume_obj.associators(wmi_result_class="Win32_DiskPartition")
            if partitions:
                disk_drive = partitions[0].associators(wmi_result_class="Win32_DiskDrive")[0]
                print("Method 1 successful.")

            # Method 2: Fallback to starting from the Logical Disk object
            if not disk_drive:
                print("Method 1 failed. Attempting fallback via LogicalDisk->Partition association...")
                logical_disks = wmi_connection.Win32_LogicalDisk(DeviceID=drive_letter)
                if logical_disks:
                    partitions = logical_disks[0].associators(wmi_result_class="Win32_DiskPartition")
                    if partitions:
                        disk_drive = partitions[0].associators(wmi_result_class="Win32_DiskDrive")[0]
                        print("Method 2 successful.")

            if not disk_drive:
                print(f"Could not find an associated Win32_DiskDrive for {drive_letter} using any method.")
                return None

            # If we found the disk_drive, collect metadata
            metadata = {
                "device_serial": disk_drive.SerialNumber.strip() if disk_drive.SerialNumber else "N/A",
                "volume_guid": volume_obj.DeviceID,
                "product_id": disk_drive.PNPDeviceID,
                "device_capacity": int(disk_drive.Size) if disk_drive.Size else 0,
                "filesystem_type": volume_obj.FileSystem,
                "insertion_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "hostname": socket.gethostname(),
                "gateway_version": "0.1.0" # Hardcoded for now
            }
            return metadata
        except IndexError:
            print(f"Could not retrieve WMI objects for {drive_letter}. It might not be a standard disk volume.")
            return None
        except Exception as e:
            print(f"An error occurred during metadata collection for {drive_letter}: {e}")
            return None

    def _handle_device_insertion(self, drive_letter):
        """
        Handles metadata collection for a new device and passes the job to the FileProcessor.
        """
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        print(f"Device inserted: {drive_letter}")

        try:
            volume = wmi_connection.Win32_Volume(DriveLetter=drive_letter)[0]
        except IndexError:
            print(f"Could not find WMI volume object for {drive_letter}. Aborting.")
            pythoncom.CoUninitialize()
            return

        # 1. Collect Metadata
        metadata = self._collect_metadata(wmi_connection, volume)
        if not metadata:
            print("Failed to collect metadata. Aborting.")
            pythoncom.CoUninitialize()
            return
            
        print("Collected Metadata:")
        for key, value in metadata.items():
            print(f"  {key}: {value}")

        # 2. Initialize Job
        job = self._job_manager.initialize_job(metadata)
        if not job:
            print("Failed to create a job. Aborting.")
            pythoncom.CoUninitialize()
            return

        # 3. Delegate to File Processor
        # The FileProcessor now handles the entire pipeline from this point forward.
        try:
            self._file_processor.process_device(job, f"{drive_letter}\\")
        except Exception as e:
            print(f"A critical error occurred in the file processor for job {job.job_id}: {e}")
            self._job_manager.update_state(job, JobState.FAILED, {"error": f"Critical failure in FileProcessor: {e}"})
        finally:
            pythoncom.CoUninitialize()

    def _handle_device_removal(self, drive_letter):
        """
        Handles the logic for a removed device.
        """
        print(f"Device removed: {drive_letter}")
        # This could be used to cancel an in-progress job for the removed device.

    def _monitor_devices(self):
        """
        Monitors for USB device insertions and removals by polling for drive letters.
        """
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        print("Starting USB device monitor (polling mode)...")
        
        known_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}

        while not self._stop_event.is_set():
            try:
                current_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}
                
                current_device_ids = set(current_volumes.keys())
                known_device_ids = set(known_volumes.keys())

                # Check for new drives (insertions)
                new_device_ids = current_device_ids - known_device_ids
                if new_device_ids:
                    for device_id in new_device_ids:
                        drive_letter = current_volumes[device_id]
                        print(f"New drive detected: {drive_letter}")
                        handler_thread = threading.Thread(
                            target=self._handle_device_insertion, 
                            args=(drive_letter,)
                        )
                        handler_thread.start()
                
                # Check for removed drives
                removed_device_ids = known_device_ids - current_device_ids
                if removed_device_ids:
                    for device_id in removed_device_ids:
                        drive_letter = known_volumes[device_id]
                        self._handle_device_removal(drive_letter)

                # Update the set of known drives for the next iteration
                known_volumes = current_volumes
                
                self._stop_event.wait(2) # Poll every 2 seconds

            except Exception as e:
                print(f"An error occurred in the polling loop: {e}")
                time.sleep(5)

        print("USB device monitor stopped.")
        pythoncom.CoUninitialize()

    def start_monitoring(self):
        """Starts the monitoring thread."""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_event.clear()
            self._monitoring_thread = threading.Thread(target=self._monitor_devices, daemon=True)
            self._monitoring_thread.start()
            print("Device monitoring started in the background.")

    def stop_monitoring(self):
        """Stops the monitoring thread."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_event.set()
            self._monitoring_thread.join(timeout=5)
            print("Device monitoring stopped.")