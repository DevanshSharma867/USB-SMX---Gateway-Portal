import unittest
from unittest.mock import patch, MagicMock, call, ANY
import sys
import time
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

# Mock wmi and pythoncom before they are imported by device_manager
mock_wmi = MagicMock()
sys.modules['wmi'] = mock_wmi
sys.modules['pythoncom'] = MagicMock()

from gateway.device_manager import DeviceManager
from gateway.job_manager import JobState # Import JobState for assertions

# A mock WMI Volume object
def create_mock_volume(drive_letter, device_id):
    vol = MagicMock()
    vol.DriveLetter = drive_letter
    vol.DeviceID = device_id
    return vol

class TestDeviceManagerAdvanced(unittest.TestCase):

    def setUp(self):
        """Patch external dependencies and initialize DeviceManager."""
        self.mock_job_manager = MagicMock()
        self.mock_file_processor = MagicMock()
        
        # Patch JobManager and FileProcessor classes during DeviceManager init
        self.job_manager_patch = patch('gateway.device_manager.JobManager', return_value=self.mock_job_manager)
        self.file_processor_patch = patch('gateway.device_manager.FileProcessor', return_value=self.mock_file_processor)
        
        self.job_manager_patch.start()
        self.file_processor_patch.start()

        # Mock the threading.Thread class
        self.mock_thread_class = patch('gateway.device_manager.threading.Thread').start()
        # Make the mocked thread's start() method execute its target function
        def _thread_side_effect(target, group=None, name=None, args=(), kwargs={}):
            mock_instance = MagicMock()
            mock_instance.start.side_effect = lambda: target(*args, **kwargs)
            return mock_instance
        self.mock_thread_class.side_effect = _thread_side_effect

        # Mock the threading.Event class
        self.mock_threading_event_class = patch('gateway.device_manager.threading.Event').start()
        self.mock_stop_event_instance = MagicMock()
        self.mock_threading_event_class.return_value = self.mock_stop_event_instance

        # Patch time.sleep and make mock_stop_event_instance.wait call it
        self.mock_sleep = patch('gateway.device_manager.time.sleep').start()
        self.mock_stop_event_instance.wait.side_effect = lambda x: self.mock_sleep(x)

        # Mock the gui_queue
        self.mock_gui_queue = MagicMock()

        self.device_manager = DeviceManager(gui_queue=self.mock_gui_queue)
        # Override the _stop_event with our mock instance
        self.device_manager._stop_event = self.mock_stop_event_instance

        # Reset mocks for each test
        mock_wmi.reset_mock()
        self.mock_job_manager.reset_mock()
        self.mock_file_processor.reset_mock()
        self.mock_gui_queue.reset_mock()
        self.mock_thread_class.reset_mock()
        self.mock_stop_event_instance.reset_mock()

        # Ensure _collect_metadata always returns something valid for simplicity in these tests
        self.patch_collect_metadata = patch.object(self.device_manager, '_collect_metadata', return_value={
            "device_serial": "TEST_SERIAL",
            "volume_guid": "TEST_GUID",
            "product_id": "TEST_PRODUCT_ID",
            "device_capacity": 1000,
            "filesystem_type": "NTFS",
            "insertion_timestamp": "2023-01-01T00:00:00Z",
            "hostname": "test-host",
            "gateway_version": "0.1.0"
        })
        self.patch_collect_metadata.start()

        # Mock JobManager.initialize_job to return a simple Job object
        self.mock_job_instance = MagicMock()
        self.mock_job_instance.job_id = "test_job_id"
        self.mock_job_instance.path = Path("mock_job_path")
        self.mock_job_manager.initialize_job.return_value = self.mock_job_instance

    def tearDown(self):
        """Stop all patches."""
        patch.stopall()

    # ===== Test _handle_device_insertion and _handle_device_removal directly =====

    def test_handle_device_insertion_success(self):
        """Test that _handle_device_insertion correctly processes a device."""
        drive_letter = 'E:'
        self.device_manager._handle_device_insertion(drive_letter)

        self.mock_job_manager.initialize_job.assert_called_once_with(ANY) # Metadata is mocked
        self.mock_file_processor.process_device.assert_called_once_with(self.mock_job_instance, f'{drive_letter}\\')
        self.mock_gui_queue.put.assert_called_once_with({
            "event": "NEW_JOB",
            "job_id": "test_job_id",
            "drive_letter": drive_letter,
            "job_path": str(self.mock_job_instance.path)
        })
        # Check that the device is tracked
        self.assertEqual(self.device_manager.active_jobs_by_drive.get(drive_letter), "test_job_id")

    def test_handle_device_removal_success(self):
        """Test that _handle_device_removal correctly processes a device removal."""
        drive_letter = 'F:'
        job_id = "removed_job_id"
        
        # Manually set up active job for removal
        self.device_manager.active_jobs_by_drive[drive_letter] = job_id

        self.device_manager._handle_device_removal(drive_letter)

        self.mock_gui_queue.put.assert_called_once_with({
            "event": "DEVICE_REMOVED",
            "job_id": job_id
        })
        # Check that the device is no longer tracked
        self.assertNotIn(drive_letter, self.device_manager.active_jobs_by_drive)

    def test_active_jobs_tracking(self):
        """Test that active_jobs_by_drive is correctly populated and cleared."""
        drive_letter = 'Z:'
        job_id = 'test_job_Z'
        self.mock_job_manager.initialize_job.return_value.job_id = job_id # Ensure job_id is what we expect

        # Simulate insertion
        self.device_manager._handle_device_insertion(drive_letter)
        self.assertEqual(self.device_manager.active_jobs_by_drive.get(drive_letter), job_id)

        # Simulate removal
        self.device_manager._handle_device_removal(drive_letter)
        self.mock_gui_queue.put.assert_has_calls([
            call({
                "event": "NEW_JOB",
                "job_id": job_id,
                "drive_letter": drive_letter,
                "job_path": str(self.mock_job_instance.path)
            }),
            call({
                "event": "DEVICE_REMOVED",
                "job_id": job_id
            })
        ])

    # ===== Test Rate Limiting Logic (_is_rate_limited) =====

    @patch('gateway.device_manager.time.time')
    def test_is_rate_limited_blocks_within_window(self, mock_time):
        """Test that _is_rate_limited blocks a device within the rate limit window."""
        device_id = "test_device_id"
        self.device_manager.rate_limit_seconds = 10

        mock_time.return_value = 100 # First call
        self.assertFalse(self.device_manager._is_rate_limited(device_id)) # Processed

        mock_time.return_value = 105 # Second call, 5 seconds later
        self.assertTrue(self.device_manager._is_rate_limited(device_id)) # Should be blocked

    @patch('gateway.device_manager.time.time')
    def test_is_rate_limited_allows_after_window(self, mock_time):
        """Test that _is_rate_limited allows a device after the rate limit window."""
        device_id = "test_device_id"
        self.device_manager.rate_limit_seconds = 10

        mock_time.return_value = 100 # First call
        self.assertFalse(self.device_manager._is_rate_limited(device_id)) # Processed

        mock_time.return_value = 111 # Second call, 11 seconds later
        self.assertFalse(self.device_manager._is_rate_limited(device_id)) # Should be allowed

    @patch('gateway.device_manager.time.time')
    def test_is_rate_limited_different_devices_not_blocked(self, mock_time):
        """Test that different devices are not rate-limited by each other."""
        self.device_manager.rate_limit_seconds = 10

        mock_time.return_value = 100
        self.assertFalse(self.device_manager._is_rate_limited("device_A"))

        mock_time.return_value = 105 # 5 seconds later
        self.assertFalse(self.device_manager._is_rate_limited("device_B")) # Should not be blocked by device A

        mock_time.return_value = 108 # 3 seconds later
        self.assertFalse(self.device_manager._is_rate_limited("device_C")) # Should not be blocked by device A or B

    # ===== Test _monitor_devices loop behavior =====

    def test_monitor_devices_single_insertion(self):
        """Test _monitor_devices loop for a single device insertion."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [], # 1st call: known_volumes
            [create_mock_volume('E:', 'device1')], # 2nd call: current_volumes (insertion)
            [create_mock_volume('E:', 'device1')], # 3rd call: _handle_device_insertion's filtered call
            [], # 4th call: current_volumes (no devices)
            [], # 5th call: current_volumes (no devices)
        ]

        # Control the loop to run twice
        self.mock_stop_event_instance.is_set.side_effect = [False, False, True]

        self.device_manager._monitor_devices()

        # Assert that _handle_device_insertion was called once
        self.mock_thread_class.assert_called_once_with(
            target=self.device_manager._handle_device_insertion,
            args=('E:',)
        )
        # Assert sleep was called twice (once per loop iteration)
        self.assertEqual(self.mock_sleep.call_count, 2)

    def test_monitor_devices_insertion_and_removal(self):
        """Test _monitor_devices loop for insertion and subsequent removal."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [], # 1st call: known_volumes
            [create_mock_volume('E:', 'device1')], # 2nd call: current_volumes (insertion)
            [create_mock_volume('E:', 'device1')], # 3rd call: _handle_device_insertion's filtered call
            [], # 4th call: current_volumes (removal)
            [], # 5th call: current_volumes (no devices)
            [], # 6th call: current_volumes (no devices)
        ]

        # Control the loop to run three times
        self.mock_stop_event_instance.is_set.side_effect = [False, False, False, True]

        self.device_manager._monitor_devices()

        # Assert _handle_device_insertion was called once
        self.mock_thread_class.assert_called_once_with(
            target=self.device_manager._handle_device_insertion,
            args=('E:',)
        )
        # Assert _handle_device_removal was called once
        self.mock_gui_queue.put.assert_has_calls([
            call({
                "event": "NEW_JOB",
                "job_id": "test_job_id",
                "drive_letter": "E:",
                "job_path": "mock_job_path"
            }),
            call({
                "event": "DEVICE_REMOVED",
                "job_id": "test_job_id"
            })
        ])
        # Assert sleep was called three times
        self.assertEqual(self.mock_sleep.call_count, 3)

    @patch('gateway.device_manager.time.sleep')
    def test_monitor_devices_wmi_error_handling(self, mock_sleep):
        """Test that the monitor loop handles WMI errors gracefully and continues."""
        mock_wmi.WMI.side_effect = [Exception("WMI Connection Error"), MagicMock(), MagicMock(), MagicMock()] # Error then success

        # Control the loop to run three times
        self.mock_stop_event_instance.is_set.side_effect = [False, False, False, True]

        self.device_manager._monitor_devices()

        # Should have called sleep after the error
        mock_sleep.assert_called_once_with(5)
        # Should have attempted to get WMI.Win32_Volume again after the error
        self.assertEqual(mock_wmi.WMI.call_count, 3)

if __name__ == '__main__':
    unittest.main()