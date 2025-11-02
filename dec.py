import os
import hashlib
import zipfile
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util import Counter


def decrypt_package(file_path: str, temp_dir: str = None):
    """
    Decrypt and unzip a Sennheiser firmware package.
    
    Args:
        file_path: Path to the encrypted .zip.enc file
        temp_dir: Temporary directory for intermediate files (default: system temp)
    
    Returns:
        bytes: The decrypted and extracted firmware data
        
    Raises:
        ValueError: If MD5 hash verification fails
    """
    # Read the encrypted file
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Set up temp directory
    if temp_dir is None:
        import tempfile
        temp_dir = tempfile.gettempdir()
    
    # Decrypt the file
    print("DECRYPT: Starting decryption...")
    key_hex = "ed3b78a474c2acabb812407b97065649bf190e3d758e86f17b920aa41d8c271e"
    key = bytes.fromhex(key_hex)
    
    # Create AES-CTR cipher with counter starting at 5
    counter = Counter.new(128, initial_value=5)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Determine filenames
    filename = os.path.basename(file_path)
    decrypted_filename = filename.replace(".enc", "")  # e.g., "file.zip.enc" -> "file.zip"
    extracted_filename = filename.replace(".zip.enc", "")  # e.g., "file.zip.enc" -> "file"
    
    decrypted_path = os.path.join(temp_dir, decrypted_filename)
    extracted_path = os.path.join(temp_dir, extracted_filename)
    md5_path = extracted_path + ".md5"
    
    # Write decrypted data to temp file
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)
    
    # Unzip the decrypted file
    print("UNZIP: Extracting archive...")
    try:
        with zipfile.ZipFile(decrypted_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
    except zipfile.BadZipFile as e:
        # Clean up temp file before raising
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)
        raise ValueError(f"Invalid zip file after decryption: {e}")
    
    # Read the extracted firmware file
    with open(extracted_path, 'rb') as f:
        firmware_data = f.read()
    
    # Calculate MD5 hash of the extracted file
    md5_calculated = hashlib.md5(firmware_data).hexdigest()
    
    # Read the expected MD5 from the .md5 file
    with open(md5_path, 'r') as f:
        md5_expected = f.read().strip()
    
    # Clean up temporary files
    if os.path.exists(decrypted_path):
        os.remove(decrypted_path)
    if os.path.exists(extracted_path):
        os.remove(extracted_path)
    if os.path.exists(md5_path):
        os.remove(md5_path)
    
    # Verify MD5 hash
    if md5_calculated == md5_expected:
        print("UNZIPPED: Successfully decrypted, extracted, and verified")
        return firmware_data
    else:
        raise ValueError(f"File is corrupted - MD5 does not match. Expected: {md5_expected}, Got: {md5_calculated}")


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python main.py <encrypted_file.zip.enc>")
        sys.exit(1)
    
    encrypted_file = sys.argv[1]
    
    try:
        firmware_data = decrypt_package(encrypted_file)
        print(f"Success! Extracted {len(firmware_data)} bytes of firmware data")
        
        # Optionally save to output file
        output_file = encrypted_file.replace(".zip.enc", "_decrypted.bin")
        with open(output_file, 'wb') as f:
            f.write(firmware_data)
        print(f"Saved decrypted firmware to: {output_file}")
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
