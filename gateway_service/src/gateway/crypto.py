# Manages cryptographic operations like encryption and signing.
import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    """Handles encryption, hashing, and digital signing."""

    def generate_cek(self, key_size_bytes: int = 32) -> bytes:
        """Generates a cryptographically secure Content Encryption Key (CEK)."""
        if key_size_bytes not in [16, 24, 32]:
            raise ValueError("Invalid key size for AES. Must be 16, 24, or 32 bytes.")
        return os.urandom(key_size_bytes)

    def encrypt_file(self, file_path: Path, cek: bytes) -> tuple[bytes, bytes, bytes] | None:
        """
        Encrypts a file using AES-256-GCM.

        Args:
            file_path: The path to the file to encrypt.
            cek: The Content Encryption Key (32 bytes for AES-256).

        Returns:
            A tuple containing (ciphertext, nonce, tag), or None on failure.
        """
        try:
            aesgcm = AESGCM(cek)
            nonce = os.urandom(12)  # GCM standard nonce size
            
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            ciphertext = aesgcm.encrypt(nonce, plaintext, None) # No associated data
            
            # The tag is appended to the ciphertext by the library, let's extract it.
            tag_length = 16 # GCM standard tag size
            actual_ciphertext = ciphertext[:-tag_length]
            tag = ciphertext[-tag_length:]

            return actual_ciphertext, nonce, tag

        except Exception as e:
            print(f"Failed to encrypt {file_path}: {e}")
            return None

    def get_sha256_hash(self, data: bytes) -> str:
        """Calculates the SHA-256 hash of a byte string."""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

    def create_manifest(self, job, file_metadata: dict) -> dict:
        """
        Creates the job manifest.
        
        Args:
            job: The job object.
            file_metadata: A dictionary mapping file paths to their metadata (hash, etc.).
        
        Returns:
            A dictionary representing the manifest.
        """
        print(f"Creating manifest for job {job.job_id}")
        manifest = {
            "job_id": job.job_id,
            "gateway_info": {
                # This would come from the device metadata collected earlier
            },
            "files": file_metadata,
            "encryption_params": {
                "algorithm": "AES-256-GCM",
                "cek_wrapped": "(placeholder - will be wrapped by Vault)"
            }
        }
        return manifest

    def sign_manifest_with_vault(self, manifest: dict) -> dict:
        """
        (Placeholder) Signs the manifest using HashiCorp Vault.
        In a real implementation, this would make a call to the Vault PKI engine.
        """
        print("Signing manifest with Vault (placeholder)...")
        # This would be replaced with an actual call to hvac library
        signed_manifest = manifest.copy()
        signed_manifest["signature"] = {
            "signer": "vault-pki-intermediate",
            "value": "(placeholder-ed25519-signature)",
            "timestamp": "(placeholder-timestamp)"
        }
        print("Manifest signed.")
        return signed_manifest

    # --- MVP Insecure Key Handling ---
    # WARNING: The following methods are for MVP purposes only and are insecure.
    # In a real system, the CEK should never be written to disk in plaintext.
    # It should be wrapped by a master key from an HSM or Vault.

    def save_cek_to_disk(self, cek: bytes, path: Path):
        """Saves the plaintext CEK to disk. INSECURE."""
        print(f"INSECURE: Saving plaintext CEK to {path}")
        with open(path, 'wb') as f:
            f.write(cek)

    def load_cek_from_disk(self, path: Path) -> bytes:
        """Loads the plaintext CEK from disk. INSECURE."""
        print(f"INSECURE: Loading plaintext CEK from {path}")
        with open(path, 'rb') as f:
            return f.read()
