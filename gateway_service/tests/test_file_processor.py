
import unittest
from unittest.mock import patch, MagicMock, call, mock_open
import sys
import tempfile
import os
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.file_processor import FileProcessor, ScanVerdict
from gateway.job_manager import Job, JobState

class TestFileProcessor(unittest.TestCase):

    def setUp(self):
        """Set up mocks for JobManager and CryptoManager."""
        self.mock_job_manager = MagicMock()
        # We instantiate FileProcessor with the mock manager
        with patch('gateway.file_processor.FileProcessor._find_mp_cmd_run', return_value='path/to/MpCmdRun.exe'):
            self.file_processor = FileProcessor(self.mock_job_manager)

    @patch('gateway.file_processor.os.walk')
    @patch('gateway.file_processor.FileProcessor.scan_file')
    @patch('gateway.file_processor.FileProcessor._get_alternate_data_streams', return_value=[])
    def test_enumerate_files_clean(self, mock_ads, mock_scan_file, mock_os_walk):
        """Test file enumeration with a set of clean files."""
        # Mock a file system structure
        mock_os_walk.return_value = [
            ('E:\\', ['dir1'], ['file1.txt']),
            ('E:\\dir1', [], ['file2.log'])
        ]
        # Mock scan results to always be CLEAN
        mock_scan_file.return_value = (ScanVerdict.CLEAN, "Clean")
        
        job = Job()
        job.state = JobState.INITIALIZED

        clean_files = self.file_processor.enumerate_files(job, "E:\\")

        self.assertEqual(len(clean_files), 2)
        self.assertEqual(str(clean_files[0]), 'E:\\dir1\\file2.log') # Sorted order
        self.assertEqual(str(clean_files[1]), 'E:\\file1.txt')
        
        # Check that the state was updated correctly
        self.mock_job_manager.update_state.assert_has_calls([
            call(job, JobState.ENUMERATING),
            call(job, JobState.SCANNING)
        ])

    @patch('gateway.file_processor.os.walk')
    @patch('gateway.file_processor.FileProcessor.scan_file')
    @patch('gateway.file_processor.FileProcessor._get_alternate_data_streams', return_value=[])
    def test_enumerate_files_malware_found(self, mock_ads, mock_scan_file, mock_os_walk):
        """Test that enumeration stops when malware is detected."""
        mock_os_walk.return_value = [('E:\\', [], ['file1.txt', 'infected.exe'])]
        
        # Make the infected file return an INFECTED verdict
        def scan_side_effect(file_path):
            if 'infected' in str(file_path):
                # This is a trick to modify job state from within the mock
                self.file_processor._job_manager.state = JobState.QUARANTINED
                return (ScanVerdict.INFECTED, "EICAR Test Virus")
            return (ScanVerdict.CLEAN, "Clean")
        mock_scan_file.side_effect = scan_side_effect
        
        job = Job()
        job.state = JobState.INITIALIZED
        # Attach the real job state to the mock so it can be updated
        self.file_processor._job_manager.state = job.state

        result_files = self.file_processor.enumerate_files(job, "E:\\")

        # Enumeration should stop, returning an empty list
        self.assertEqual(len(result_files), 0)
        # Check that the job state was set to QUARANTINED
        self.mock_job_manager.update_state.assert_any_call(job, JobState.QUARANTINED)

    @patch('gateway.file_processor.subprocess.run')
    def test_scan_file_defender_infected(self, mock_subprocess_run):
        """Test the scan_file method with a mock infected result from Defender."""
        mock_process_result = MagicMock()
        mock_process_result.stdout = "Threat found: Trojan:Win32/Wacatac.B!ml"
        mock_subprocess_run.return_value = mock_process_result

        verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))

        self.assertEqual(verdict, ScanVerdict.INFECTED)
        self.assertIn("Defender", details)

    @patch('gateway.file_processor.subprocess.run')
    def test_scan_file_clamav_infected(self, mock_subprocess_run):
        """Test the scan_file method with a mock infected result from ClamAV."""
        # First call to Defender raises FileNotFoundError, second to ClamAV finds a virus
        mock_subprocess_run.side_effect = [
            FileNotFoundError,
            MagicMock(stdout="C:\\test.exe: Eicar-Test-Signature FOUND", returncode=1)
        ]

        verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))

        self.assertEqual(verdict, ScanVerdict.INFECTED)
        self.assertIn("ClamAV", details)

    @patch('gateway.file_processor.subprocess.run', side_effect=FileNotFoundError)
    def test_scan_file_no_scanners_found(self, mock_subprocess_run):
        """Test that the verdict is CLEAN if no scanners are found."""
        verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
        self.assertEqual(verdict, ScanVerdict.CLEAN)
        self.assertEqual(details, "Scanners not found")

    @patch('gateway.file_processor.CryptoManager')
    @patch('builtins.open', new_callable=mock_open)
    def test_package_job(self, mock_open_file, mock_crypto_manager):
        """Test the job packaging process."""
        # Mock instances and their method return values
        mock_crypto_instance = mock_crypto_manager.return_value
        mock_crypto_instance.generate_cek.return_value = b'0' * 32
        mock_crypto_instance.encrypt_file.return_value = (b'ciphertext', b'nonce', b'tag')
        mock_crypto_instance.get_sha256_hash.return_value = 'file_hash'
        mock_crypto_instance.create_manifest.return_value = {'manifest': 'data'}
        mock_crypto_instance.sign_manifest_with_vault.return_value = {'signed': 'manifest'}

        job = Job()
        file_list = [Path('E:/file1.txt')]
        self.file_processor.package_job(job, file_list)

        # Verify encryption was called
        mock_crypto_instance.encrypt_file.assert_called_once_with(Path('E:/file1.txt'), b'0' * 32)
        # Verify the encrypted blob was written
        mock_open_file.assert_called_with(job.path / 'data' / 'file_hash', 'wb')
        # Verify manifest was created and signed
        mock_crypto_instance.create_manifest.assert_called_once()
        mock_crypto_instance.sign_manifest_with_vault.assert_called_once()
        # Verify the final state update with the manifest
        self.mock_job_manager.update_state.assert_called_with(job, JobState.SUCCESS, {'manifest': {'signed': 'manifest'}})

    def test_is_path_safe_valid_paths(self):
        """Test that valid paths within root are considered safe."""
        root = Path("E:\\")
        
        # Valid paths within root
        self.assertTrue(self.file_processor._is_path_safe(Path("E:\\file.txt"), root))
        self.assertTrue(self.file_processor._is_path_safe(Path("E:\\folder\\file.txt"), root))
        self.assertTrue(self.file_processor._is_path_safe(Path("E:\\folder\\subfolder\\file.txt"), root))
        
        # Root itself should be safe
        self.assertTrue(self.file_processor._is_path_safe(root, root))

    def test_is_path_safe_path_traversal_attacks(self):
        """Test that path traversal attacks are detected and blocked."""
        root = Path("E:\\")
        
        # Path traversal attacks
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\..\\file.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\folder\\..\\..\\file.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\folder\\..\\..\\..\\file.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\..\\..\\file.txt"), root))
        
        # Mixed traversal attempts
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\folder\\..\\..\\..\\..\\file.txt"), root))

    def test_is_path_safe_absolute_paths_outside_root(self):
        """Test that absolute paths outside root are blocked."""
        root = Path("E:\\")
        
        # Paths outside root
        self.assertFalse(self.file_processor._is_path_safe(Path("C:\\file.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path("D:\\file.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path("F:\\file.txt"), root))

    def test_is_path_safe_invalid_paths(self):
        """Test that invalid paths are handled safely."""
        root = Path("E:\\")
        
        # Invalid characters and paths
        self.assertFalse(self.file_processor._is_path_safe(Path("E:\\file\x00.txt"), root))
        self.assertFalse(self.file_processor._is_path_safe(Path(""), root))
        
        # Very long paths
        long_path = Path("E:\\" + "x" * 1000 + "\\file.txt")
        self.assertFalse(self.file_processor._is_path_safe(long_path, root))

    @patch('gateway.file_processor.FileProcessor._kernel32')
    def test_get_alternate_data_streams_no_streams(self, mock_kernel32):
        """Test ADS detection when no alternate data streams exist."""
        # Mock FindFirstStreamW to return INVALID_HANDLE_VALUE (no streams)
        mock_kernel32.FindFirstStreamW.return_value = -1  # INVALID_HANDLE_VALUE
        
        result = self.file_processor._get_alternate_data_streams(Path("E:\\file.txt"))
        
        self.assertEqual(result, [])
        mock_kernel32.FindFirstStreamW.assert_called_once()

    @patch('gateway.file_processor.FileProcessor._kernel32')
    def test_get_alternate_data_streams_with_streams(self, mock_kernel32):
        """Test ADS detection when alternate data streams exist."""
        # Mock stream data
        mock_stream_data = MagicMock()
        mock_stream_data.cStreamName = ":Zone.Identifier:$DATA"
        
        # Mock FindFirstStreamW to return a valid handle
        mock_kernel32.FindFirstStreamW.return_value = 123
        mock_kernel32.FindNextStreamW.side_effect = [True, False]  # Two streams, then done
        mock_kernel32.FindClose.return_value = True
        
        # Create a mock for the stream data structure
        with patch('gateway.file_processor.WIN32_FIND_STREAM_DATA', return_value=mock_stream_data):
            result = self.file_processor._get_alternate_data_streams(Path("E:\\file.txt"))
        
        self.assertEqual(len(result), 2)  # Two streams found
        mock_kernel32.FindFirstStreamW.assert_called_once()
        mock_kernel32.FindNextStreamW.assert_called_once()
        mock_kernel32.FindClose.assert_called_once_with(123)

    @patch('gateway.file_processor.FileProcessor._kernel32')
    def test_get_alternate_data_streams_api_error(self, mock_kernel32):
        """Test ADS detection when Windows API returns an error."""
        # Mock FindFirstStreamW to return INVALID_HANDLE_VALUE
        mock_kernel32.FindFirstStreamW.return_value = -1
        
        result = self.file_processor._get_alternate_data_streams(Path("E:\\file.txt"))
        
        self.assertEqual(result, [])
        mock_kernel32.FindFirstStreamW.assert_called_once()

    def test_scan_file_defender_timeout(self):
        """Test Defender scan timeout handling."""
        with patch('gateway.file_processor.subprocess.run', side_effect=subprocess.TimeoutExpired("cmd", 120)):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.TIMEOUT)
            self.assertIn("timed out", details)

    def test_scan_file_clamav_timeout(self):
        """Test ClamAV scan timeout handling."""
        with patch('gateway.file_processor.subprocess.run', side_effect=[
            FileNotFoundError,  # Defender not found
            subprocess.TimeoutExpired("clamscan", 120)  # ClamAV timeout
        ]):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.TIMEOUT)
            self.assertIn("timed out", details)

    def test_scan_file_defender_error_but_clean(self):
        """Test Defender error but output shows clean."""
        mock_result = MagicMock()
        mock_result.stdout = "Threats found: 0"
        with patch('gateway.file_processor.subprocess.run', side_effect=subprocess.CalledProcessError(1, "cmd", "error", "Threats found: 0")):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.CLEAN)

    def test_scan_file_defender_error_with_threats(self):
        """Test Defender error but output shows threats."""
        with patch('gateway.file_processor.subprocess.run', side_effect=subprocess.CalledProcessError(1, "cmd", "error", "Threats found: 1")):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.INFECTED)

    def test_scan_file_clamav_error_code_1(self):
        """Test ClamAV error code 1 (virus found)."""
        with patch('gateway.file_processor.subprocess.run', side_effect=[
            FileNotFoundError,  # Defender not found
            subprocess.CalledProcessError(1, "clamscan", "C:\\test.exe: Eicar-Test-Signature FOUND")
        ]):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.INFECTED)
            self.assertIn("ClamAV", details)

    def test_scan_file_clamav_other_error(self):
        """Test ClamAV error code other than 1."""
        with patch('gateway.file_processor.subprocess.run', side_effect=[
            FileNotFoundError,  # Defender not found
            subprocess.CalledProcessError(2, "clamscan", "Some other error")
        ]):
            verdict, details = self.file_processor.scan_file(Path('C:/test.exe'))
            self.assertEqual(verdict, ScanVerdict.ERROR)
            self.assertIn("error (code 2)", details)

    @patch('gateway.file_processor.os.walk')
    def test_enumerate_files_exception_handling(self, mock_os_walk):
        """Test that exceptions during enumeration are handled properly."""
        mock_os_walk.side_effect = Exception("File system error")
        
        job = Job()
        job.state = JobState.INITIALIZED
        
        result = self.file_processor.enumerate_files(job, "E:\\")
        
        self.assertEqual(len(result), 0)
        self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED)

    @patch('gateway.file_processor.os.walk')
    @patch('gateway.file_processor.FileProcessor.scan_file')
    @patch('gateway.file_processor.FileProcessor._get_alternate_data_streams')
    def test_enumerate_files_unsafe_paths_skipped(self, mock_ads, mock_scan_file, mock_os_walk):
        """Test that unsafe paths are skipped during enumeration."""
        mock_os_walk.return_value = [
            ('E:\\', [], ['safe_file.txt', '..\\unsafe_file.txt'])
        ]
        mock_scan_file.return_value = (ScanVerdict.CLEAN, "Clean")
        mock_ads.return_value = []
        
        # Mock _is_path_safe to return False for unsafe paths
        def mock_is_path_safe(path, root):
            return "unsafe" not in str(path)
        
        with patch.object(self.file_processor, '_is_path_safe', side_effect=mock_is_path_safe):
            job = Job()
            job.state = JobState.INITIALIZED
            
            result = self.file_processor.enumerate_files(job, "E:\\")
            
            # Only safe file should be included
            self.assertEqual(len(result), 1)
            self.assertEqual(str(result[0]), 'E:\\safe_file.txt')

    @patch('gateway.file_processor.CryptoManager')
    def test_package_job_encryption_failure(self, mock_crypto_manager):
        """Test job packaging when file encryption fails."""
        mock_crypto_instance = mock_crypto_manager.return_value
        mock_crypto_instance.generate_cek.return_value = b'0' * 32
        mock_crypto_instance.encrypt_file.return_value = None  # Encryption fails
        
        job = Job()
        file_list = [Path('E:/file1.txt')]
        
        self.file_processor.package_job(job, file_list)
        
        # Should update state to FAILED
        self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED)

    @patch('gateway.file_processor.CryptoManager')
    @patch('builtins.open', new_callable=mock_open)
    def test_package_job_file_write_failure(self, mock_open_file, mock_crypto_manager):
        """Test job packaging when file writing fails."""
        mock_crypto_instance = mock_crypto_manager.return_value
        mock_crypto_instance.generate_cek.return_value = b'0' * 32
        mock_crypto_instance.encrypt_file.return_value = (b'ciphertext', b'nonce', b'tag')
        mock_crypto_instance.get_sha256_hash.return_value = 'file_hash'
        mock_crypto_instance.create_manifest.return_value = {'manifest': 'data'}
        mock_crypto_instance.sign_manifest_with_vault.return_value = {'signed': 'manifest'}
        
        # Make file writing fail
        mock_open_file.side_effect = IOError("Disk full")
        
        job = Job()
        file_list = [Path('E:/file1.txt')]
        
        self.file_processor.package_job(job, file_list)
        
        # Should update state to FAILED
        self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED)

    def test_find_mp_cmd_run_found(self):
        """Test finding MpCmdRun.exe in standard locations."""
        with patch('pathlib.Path.exists', return_value=True):
            result = self.file_processor._find_mp_cmd_run()
            self.assertIsNotNone(result)

    def test_find_mp_cmd_run_not_found(self):
        """Test when MpCmdRun.exe is not found."""
        with patch('pathlib.Path.exists', return_value=False):
            result = self.file_processor._find_mp_cmd_run()
            self.assertIsNone(result)

    def test_find_mp_cmd_run_platform_directory(self):
        """Test finding MpCmdRun.exe in platform directory."""
        with patch('pathlib.Path.exists') as mock_exists:
            def exists_side_effect(path):
                return str(path).endswith("MpCmdRun.exe")
            
            mock_exists.side_effect = exists_side_effect
            
            with patch('pathlib.Path.iterdir', return_value=[Path("4.18.2205.7-0")]):
                with patch('pathlib.Path.is_dir', return_value=True):
                    result = self.file_processor._find_mp_cmd_run()
                    self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()
