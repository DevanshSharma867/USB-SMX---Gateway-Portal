
import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Add the src directory to the Python path to allow for module imports
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.crypto import CryptoManager

class TestCryptoManager(unittest.TestCase):

    def setUp(self):
        """Set up for each test."""
        self.crypto_manager = CryptoManager()
        self.test_data = b"This is a test file for encryption."
        self.test_file = Path("test_file.tmp")
        with open(self.test_file, "wb") as f:
            f.write(self.test_data)

    def tearDown(self):
        """Clean up after each test."""
        if self.test_file.exists():
            self.test_file.unlink()

    def test_generate_cek(self):
        """Test that the Content Encryption Key is generated with the correct length."""
        cek = self.crypto_manager.generate_cek(key_size_bytes=32)
        self.assertEqual(len(cek), 32)
        
        cek = self.crypto_manager.generate_cek(key_size_bytes=16)
        self.assertEqual(len(cek), 16)

        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=10) # Invalid size

    def test_get_sha256_hash(self):
        """Test SHA-256 hash generation with a known value."""
        known_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        calculated_hash = self.crypto_manager.get_sha256_hash(b"hello world")
        self.assertEqual(calculated_hash, known_hash)

    def test_encrypt_file_and_decrypt(self):
        """
        Test that a file can be encrypted and that the resulting ciphertext
        can be decrypted back to the original plaintext.
        """
        cek = self.crypto_manager.generate_cek()
        encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
        
        self.assertIsNotNone(encryption_result)
        ciphertext, nonce, tag = encryption_result
        
        # Ensure ciphertext is different from plaintext
        self.assertNotEqual(ciphertext, self.test_data)
        
        # Manually decrypt to verify correctness
        aesgcm = AESGCM(cek)
        # The library expects the tag to be appended to the ciphertext for decryption
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        
        self.assertEqual(decrypted_data, self.test_data)

    def test_create_manifest(self):
        """Test the structure of the generated manifest."""
        # Mock job and file data
        class MockJob:
            job_id = "mock-job-123"
        
        mock_file_data = {
            "C:\\path\\file1.txt": {"sha256_encrypted": "hash1"},
            "C:\\path\\file2.log": {"sha256_encrypted": "hash2"},
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), mock_file_data)
        
        self.assertEqual(manifest["job_id"], "mock-job-123")
        self.assertIn("gateway_info", manifest)
        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]),
 2)
        self.assertIn("encryption_params", manifest)
        self.assertEqual(manifest["encryption_params"]["algorithm"], "AES-256-GCM")

    def test_sign_manifest_with_vault_placeholder(self):
        """Test that the placeholder signing function adds the signature block."""
        manifest = {"job_id": "test"}
        signed_manifest = self.crypto_manager.sign_manifest_with_vault(manifest)
        
        self.assertIn("signature", signed_manifest)
        self.assertEqual(signed_manifest["signature"]["value"], "(placeholder-ed25519-signature)")

    def test_encrypt_file_nonexistent_file(self):
        """Test encryption of a non-existent file returns None."""
        nonexistent_file = Path("nonexistent_file.txt")
        cek = self.crypto_manager.generate_cek()
        
        result = self.crypto_manager.encrypt_file(nonexistent_file, cek)
        self.assertIsNone(result)

    def test_encrypt_file_permission_error(self):
        """Test encryption when file cannot be read due to permissions."""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(self.test_file, cek)
            self.assertIsNone(result)

    def test_encrypt_file_empty_file(self):
        """Test encryption of an empty file."""
        empty_file = Path("empty_file.tmp")
        empty_file.touch()
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(empty_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            self.assertEqual(len(ciphertext), 0)  # Empty file should produce empty ciphertext
        finally:
            if empty_file.exists():
                empty_file.unlink()

    def test_encrypt_file_large_file(self):
        """Test encryption of a large file."""
        large_file = Path("large_file.tmp")
        large_data = b"X" * (1024 * 1024)  # 1MB of data
        
        with open(large_file, "wb") as f:
            f.write(large_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(large_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            self.assertEqual(len(ciphertext), len(large_data))
        finally:
            if large_file.exists():
                large_file.unlink()

    def test_generate_cek_invalid_sizes(self):
        """Test that invalid key sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=8)
        
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=64)
        
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=0)

    def test_get_sha256_hash_edge_cases(self):
        """Test SHA-256 hash with edge cases."""
        # Empty data
        empty_hash = self.crypto_manager.get_sha256_hash(b"")
        self.assertEqual(len(empty_hash), 64)  # SHA-256 produces 64 hex chars
        
        # Very long data
        long_data = b"X" * 10000
        long_hash = self.crypto_manager.get_sha256_hash(long_data)
        self.assertEqual(len(long_hash), 64)
        
        # Binary data
        binary_data = bytes(range(256))
        binary_hash = self.crypto_manager.get_sha256_hash(binary_data)
        self.assertEqual(len(binary_hash), 64)

    def test_create_manifest_with_empty_files(self):
        """Test manifest creation with empty file metadata."""
        class MockJob:
            job_id = "empty-job-123"
        
        empty_file_data = {}
        manifest = self.crypto_manager.create_manifest(MockJob(), empty_file_data)
        
        self.assertEqual(manifest["job_id"], "empty-job-123")
        self.assertEqual(len(manifest["files"]), 0)
        self.assertIn("encryption_params", manifest)

    def test_create_manifest_with_large_file_list(self):
        """Test manifest creation with many files."""
        class MockJob:
            job_id = "large-job-456"
        
        # Create a large file metadata dictionary
        large_file_data = {}
        for i in range(1000):
            large_file_data[f"C:\\path\\file{i}.txt"] = {"sha256_encrypted": f"hash{i}"}
        
        manifest = self.crypto_manager.create_manifest(MockJob(), large_file_data)
        
        self.assertEqual(manifest["job_id"], "large-job-456")
        self.assertEqual(len(manifest["files"]), 1000)

    def test_sign_manifest_preserves_original(self):
        """Test that signing doesn't modify the original manifest."""
        original_manifest = {"job_id": "test", "files": {"file1.txt": "hash1"}}
        signed_manifest = self.crypto_manager.sign_manifest_with_vault(original_manifest)
        
        # Original should not have signature
        self.assertNotIn("signature", original_manifest)
        # Signed should have signature
        self.assertIn("signature", signed_manifest)
        # Other fields should be preserved
        self.assertEqual(signed_manifest["job_id"], original_manifest["job_id"])
        self.assertEqual(signed_manifest["files"], original_manifest["files"])

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt-decrypt roundtrip produces original data."""
        cek = self.crypto_manager.generate_cek()
        encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
        
        self.assertIsNotNone(encryption_result)
        ciphertext, nonce, tag = encryption_result
        
        # Decrypt using the same method as in the test
        aesgcm = AESGCM(cek)
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        
        self.assertEqual(decrypted_data, self.test_data)

    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext for same input."""
        cek1 = self.crypto_manager.generate_cek()
        cek2 = self.crypto_manager.generate_cek()
        
        result1 = self.crypto_manager.encrypt_file(self.test_file, cek1)
        result2 = self.crypto_manager.encrypt_file(self.test_file, cek2)
        
        self.assertNotEqual(result1[0], result2[0])  # Different ciphertext
        self.assertNotEqual(result1[1], result2[1])  # Different nonces

if __name__ == '__main__':
    unittest.main()
