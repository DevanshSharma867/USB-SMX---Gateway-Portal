#!/usr/bin/env python
"""
Standalone script to decrypt the output of a Gateway Service job.
"""
import sys
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Error: The 'cryptography' library is required. Please install it using 'pip install cryptography'")
    sys.exit(1)

# --- Configuration ---
JOBS_DIR = Path(__file__).parent / "jobs"

def main():
    """Main function to run the decryption process."""
    # 1. Get Job ID from command line argument
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <job_id>")
        print(f"Example: python {sys.argv[0]} b906af11-2616-4065-948a-0905159cba9a")
        sys.exit(1)
    
    job_id = sys.argv[1]
    job_dir = JOBS_DIR / job_id

    print(f"--- Decrypting Job: {job_id} ---")

    # 2. Validate paths
    manifest_path = job_dir / "manifest.json"
    key_path = job_dir / "cek.key"
    data_dir = job_dir / "data"
    output_dir = job_dir / "output"

    if not job_dir.is_dir():
        print(f"Error: Job directory not found at {job_dir}")
        sys.exit(1)
    
    if not all([manifest_path.is_file(), key_path.is_file(), data_dir.is_dir()]):
        print("Error: Job directory is incomplete. Missing manifest.json, cek.key, or data/ directory.")
        sys.exit(1)

    # 3. Load key and manifest
    print("Loading decryption key and manifest...")
    try:
        cek = key_path.read_bytes()
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"Error reading job files: {e}")
        sys.exit(1)

    # 4. Create output directory
    output_dir.mkdir(exist_ok=True)
    print(f"Output will be saved to: {output_dir}")

    # 5. Decryption Loop
    files_to_decrypt = manifest.get('files', {})
    if not files_to_decrypt:
        print("Warning: Manifest contains no files to decrypt.")
        sys.exit(0)

    success_count = 0
    fail_count = 0

    for original_path_str, file_data in files_to_decrypt.items():
        original_path = Path(original_path_str)
        print(f"\nProcessing: {original_path.name}")

        try:
            # Reconstruct the full path for the output file
            relative_path = original_path.relative_to(original_path.anchor)
            output_file_path = output_dir / relative_path
            output_file_path.parent.mkdir(parents=True, exist_ok=True)

            # Get crypto material from manifest
            encrypted_blob_name = file_data['encrypted_blob_name']
            nonce = bytes.fromhex(file_data['nonce'])
            tag = bytes.fromhex(file_data['tag'])

            # Read the encrypted data blob
            encrypted_blob_path = data_dir / encrypted_blob_name
            ciphertext = encrypted_blob_path.read_bytes()

            # Decrypt using AES-GCM
            aesgcm = AESGCM(cek)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)

            # Write the decrypted plaintext to the output file
            output_file_path.write_bytes(plaintext)
            print(f"  -> Decrypted successfully to {output_file_path}")
            success_count += 1

        except InvalidTag:
            print("  -> ERROR: Decryption failed! The file is corrupt or the key is incorrect (Invalid Tag).")
            fail_count += 1
        except Exception as e:
            print(f"  -> ERROR: An unexpected error occurred: {e}")
            fail_count += 1

    print(f"\n--- Decryption Complete ---")
    print(f"Successfully decrypted: {success_count} file(s)")
    print(f"Failed to decrypt:    {fail_count} file(s)")

if __name__ == "__main__":
    main()
