import os
import base64
import zipfile
import tempfile
import secrets
import string
import hashlib
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

CHUNK_SIZE = 64 * 1024  # 64 KB chunk size for memory efficiency
PBKDF2_ITERATIONS = 600_000  # OWASP security standard for password hashing

class SecureVault:
    @staticmethod
    def print_progress(iteration, total, prefix='Progress:', suffix='Complete', length=40, fill='█'):
        """Call in a loop to create terminal progress bar"""
        if total <= 0:  # Prevent division by zero for empty files
            total = 1
            iteration = 1
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration >= total:
            print()  # Print New Line on Complete

    @staticmethod
    def derive_key(secret: bytes, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from a secret (password or key file bytes) and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(secret)

    # --- TEXT ENCRYPTION ---
    @staticmethod
    def encrypt_data(secret: bytes, plaintext: str) -> str:
        salt = os.urandom(16)
        key = SecureVault.derive_key(secret, salt)
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        payload = salt + nonce + ciphertext
        return base64.b64encode(payload).decode('utf-8')

    @staticmethod
    def decrypt_data(secret: bytes, encrypted_b64: str) -> str:
        encrypted_payload = base64.b64decode(encrypted_b64)
        
        salt = encrypted_payload[:16]
        nonce = encrypted_payload[16:28]
        ciphertext = encrypted_payload[28:]
        
        key = SecureVault.derive_key(secret, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

    # --- FILE ENCRYPTION ---
    @staticmethod
    def encrypt_file(secret: bytes, input_path: str, output_path: str):
        salt = os.urandom(16)
        key = SecureVault.derive_key(secret, salt)
        aesgcm = AESGCM(key)
        
        total_size = os.path.getsize(input_path)
        processed_size = 0
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            SecureVault.print_progress(0, total_size)
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                nonce = os.urandom(12)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                payload = nonce + encrypted_chunk
                
                f_out.write(len(payload).to_bytes(4, byteorder='big'))
                f_out.write(payload)
                
                processed_size += len(chunk)
                SecureVault.print_progress(processed_size, total_size)
                
            # Guarantee 100% completion print for empty files
            if total_size == 0:
                SecureVault.print_progress(1, 1)

    @staticmethod
    def decrypt_file(secret: bytes, input_path: str, output_path: str):
        total_size = os.path.getsize(input_path)
        processed_size = 0
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            salt = f_in.read(16)
            if len(salt) < 16:
                raise ValueError("Corrupted file header (salt missing).")
            processed_size += 16
            
            key = SecureVault.derive_key(secret, salt)
            aesgcm = AESGCM(key)
            
            SecureVault.print_progress(processed_size, total_size)
            
            while True:
                size_bytes = f_in.read(4)
                if not size_bytes:
                    break
                processed_size += 4
                
                payload_len = int.from_bytes(size_bytes, byteorder='big')
                payload = f_in.read(payload_len)
                processed_size += payload_len
                
                nonce = payload[:12]
                ciphertext = payload[12:]
                
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext, None)
                f_out.write(decrypted_chunk)
                
                SecureVault.print_progress(min(processed_size, total_size), total_size)

    # --- FOLDER ENCRYPTION ---
    @staticmethod
    def encrypt_folder(secret: bytes, folder_path: str, output_path: str):
        folder_path = os.path.abspath(folder_path)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_zip_path = os.path.join(temp_dir, "temp_archive.zip")
            
            print("Zipping folder contents (this may take a moment)...")
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)
                        
            print("Encrypting archive...")
            SecureVault.encrypt_file(secret, temp_zip_path, output_path)

    @staticmethod
    def decrypt_folder(secret: bytes, input_path: str, output_folder_path: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_zip_path = os.path.join(temp_dir, "temp_archive.zip")
            
            print("Decrypting archive...")
            SecureVault.decrypt_file(secret, input_path, temp_zip_path)
            
            print("Extracting folder contents...")
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                zipf.extractall(output_folder_path)

    # --- FILE HASHING ---
    @staticmethod
    def hash_file(file_path: str, algorithm: str = 'sha256') -> str:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            hasher = hashlib.new(algorithm)
        except ValueError as exc:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}") from exc

        file_size = os.path.getsize(file_path)
        processed_size = 0

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                processed_size += len(chunk)
                SecureVault.print_progress(processed_size, file_size, prefix=f'Hashing {algorithm.upper()}:')

        if file_size == 0:
            SecureVault.print_progress(1, 1, prefix=f'Hashing {algorithm.upper()}:')

        return hasher.hexdigest()

    # --- SHREDDING / SECURE DELETION ---
    @staticmethod
    def shred_file(file_path: str, passes: int = 2):
        if not os.path.exists(file_path):
            return
            
        file_size = os.path.getsize(file_path)
        total_work = max(file_size * passes, 1)
        completed_work = 0
        
        with open(file_path, 'ba+', buffering=0) as f:
            SecureVault.print_progress(0, total_work, prefix='Shredding:')
            for _ in range(passes):
                f.seek(0)
                written = 0
                while written < file_size:
                    chunk = min(CHUNK_SIZE, file_size - written)
                    f.write(os.urandom(chunk))
                    written += chunk
                    completed_work += chunk
                    SecureVault.print_progress(completed_work, total_work, prefix='Shredding:')
                f.flush()
                os.fsync(f.fileno())
                
        os.remove(file_path)

    @staticmethod
    def shred_folder(folder_path: str):
        if not os.path.exists(folder_path):
            return
            
        # Get total files to shred for folder progress
        files_to_shred = []
        for root, _, files in os.walk(folder_path, topdown=False):
            for file in files:
                files_to_shred.append(os.path.join(root, file))
                
        total_files = len(files_to_shred)
        for index, file_path in enumerate(files_to_shred, start=1):
            print(f"Shredding file {index}/{total_files}...")
            SecureVault.shred_file(file_path)
            
        for root, dirs, _ in os.walk(folder_path, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                os.rmdir(dir_path)
                
        os.rmdir(folder_path)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def generate_secure_password() -> str:
    """Generates a cryptographically strong 256-bit hex password (terminal safe)."""
    return secrets.token_hex(32)


def get_auth_secret(is_encryption=True) -> bytes:
    """Prompts the user to authenticate via password or key file and returns raw bytes."""
    print("\nAuthentication Options:")
    print("  [1] Enter a custom password")
    print("  [2] Use a Key File")
    if is_encryption:
        print("  [3] Auto-generate a secure random password")
        print("  [4] Auto-generate and save a new Key File")
        max_opt = 4
    else:
        max_opt = 2

    while True:
        choice = input(f"Select option (1-{max_opt}): ").strip()
        
        if choice == '1':
            return getpass.getpass("Enter password (input hidden):\n> ").strip('\r\n').encode('utf-8')
            
        elif choice == '2':
            kf_path = input("Drag and drop Key File here (or type path):\n> ").strip('"\' ')
            if not os.path.exists(kf_path):
                print(f"\n[ERROR] Key file '{kf_path}' does not exist.")
                continue
            try:
                with open(kf_path, 'rb') as f:
                    secret = f.read()
                    if not secret:
                        print("\n[ERROR] Key file is empty.")
                        continue
                    return secret
            except Exception as e:
                print(f"\n[ERROR] Could not read key file: {e}")
                continue
                
        elif choice == '3' and is_encryption:
            generated_password = generate_secure_password()
            print("\n========================================")
            print("  YOUR GENERATED PASSWORD:")
            print(f"  {generated_password}")
            print("========================================")
            print("IMPORTANT: Save this password! If you lose it, data cannot be recovered.")
            input("\nPress Enter once you have saved your password...")
            return generated_password.encode('utf-8')
            
        elif choice == '4' and is_encryption:
            kf_name = input("Enter filename for the new Key File (e.g., my_secret.key):\n> ").strip('"\' ')
            if not kf_name:
                print("\n[ERROR] Invalid filename.")
                continue
                
            # Get the directory where the Python script is running from
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Extract just the filename (in case the user accidentally typed a path)
            kf_filename = os.path.basename(kf_name)
            kf_path = os.path.join(script_dir, kf_filename)
            
            if os.path.exists(kf_path):
                if input(f"\n[WARNING] File '{kf_path}' already exists. Overwrite? (y/N): ").strip().lower() != 'y':
                    continue
            try:
                # 64 bytes (512 bits) of cryptographic entropy for the key file
                secret = os.urandom(64) 
                with open(kf_path, 'wb') as f:
                    f.write(secret)
                print("\n========================================")
                print(f"  KEY FILE CREATED: {kf_path}")
                print("========================================")
                print("IMPORTANT: Backup this key file! If you lose it, data cannot be recovered.")
                input("\nPress Enter once you have backed it up...")
                return secret
            except Exception as e:
                print(f"\n[ERROR] Could not create key file: {e}")
                continue
        else:
            print("\n[ERROR] Invalid selection.")


def main():
    while True:
        clear_screen()
        print("========================================")
        print("          ULTRA SECURE VAULT            ")
        print("      (AES-256-GCM + PBKDF2 KDF)        ")
        print("========================================")
        print("\nSelect an option:")
        print("  [1] Encrypt a text message")
        print("  [2] Decrypt a text message")
        print("  [3] Encrypt a file")
        print("  [4] Decrypt a file")
        print("  [5] Encrypt a folder (ZIP + AES)")
        print("  [6] Decrypt a folder")
        print("  [7] Shred a file or folder (without encrypting)")
        print("  [8] Hash a file")
        print("  [9] Exit")
        
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == '1':
            print("\n--- ENCRYPT TEXT ---")
            message = input("Enter text message to encrypt:\n> ")
            secret = get_auth_secret(is_encryption=True)
            try:
                encrypted_msg = SecureVault.encrypt_data(secret, message)
                print("\n[SUCCESS] Save this encrypted payload:")
                print("========================================")
                print(f"{encrypted_msg}")
                print("========================================")
            except Exception as e:
                print(f"\n[ERROR] Encryption failed: {e}")
                
        elif choice == '2':
            print("\n--- DECRYPT TEXT ---")
            encrypted_msg = input("Paste ENCRYPTED MESSAGE:\n> ").strip()
            secret = get_auth_secret(is_encryption=False)
            try:
                decrypted_msg = SecureVault.decrypt_data(secret, encrypted_msg)
                print("\n========================================")
                print(f"DECRYPTED MESSAGE:\n{decrypted_msg}")
                print("========================================")
            except InvalidTag:
                print("\n[ERROR] Decryption failed! Incorrect password/keyfile or modified message.")
            except Exception as e:
                print(f"\n[ERROR] Failed to process payload: {e}")

        elif choice == '3':
            print("\n--- ENCRYPT FILE ---")
            file_path = input("Drag and drop file here (or type path):\n> ").strip('"\' ')
            
            if not os.path.exists(file_path):
                print("\n[ERROR] File does not exist!")
            else:
                secret = get_auth_secret(is_encryption=True)
                output_path = file_path + ".enc"
                
                # Check for accidental overwrite
                if os.path.exists(output_path):
                    print(f"\n[WARNING] The file '{output_path}' already exists.")
                    if input("Overwrite it? (y/N): ").strip().lower() != 'y':
                        print("Operation cancelled.")
                        continue
                        
                try:
                    print("\nEncrypting file...")
                    SecureVault.encrypt_file(secret, file_path, output_path)
                    print(f"[SUCCESS] Encrypted file created: {output_path}")
                    
                    shred_choice = input("\nDo you want to SHRED the original unencrypted file? (y/N): ").strip().lower()
                    if shred_choice == 'y':
                        SecureVault.shred_file(file_path)
                        print("[SUCCESS] Original file permanently destroyed.")
                        
                except Exception as e:
                    print(f"\n[ERROR] File encryption failed: {e}")

        elif choice == '4':
            print("\n--- DECRYPT FILE ---")
            file_path = input("Drag and drop .enc file here (or type path):\n> ").strip('"\' ')
            
            if not os.path.exists(file_path):
                print("\n[ERROR] File does not exist!")
            else:
                secret = get_auth_secret(is_encryption=False)
                if file_path.endswith(".enc"):
                    output_path = file_path[:-4]
                else:
                    output_path = file_path + ".decrypted"
                    
                if os.path.exists(output_path):
                    print(f"\n[WARNING] The file '{output_path}' already exists.")
                    if input("Overwrite it? (y/N): ").strip().lower() != 'y':
                        print("Operation cancelled.")
                        continue
                        
                try:
                    print("\nDecrypting file...")
                    SecureVault.decrypt_file(secret, file_path, output_path)
                    print(f"[SUCCESS] Restored file to: {output_path}")
                except InvalidTag:
                    print("\n[ERROR] Decryption failed! Incorrect password/keyfile or corrupted file.")
                except Exception as e:
                    print(f"\n[ERROR] Could not decrypt file: {e}")

        elif choice == '5':
            print("\n--- ENCRYPT FOLDER ---")
            folder_path = input("Drag and drop folder here (or type path):\n> ").strip('"\' ')
            
            if not os.path.isdir(folder_path):
                print("\n[ERROR] Directory does not exist!")
            else:
                secret = get_auth_secret(is_encryption=True)
                clean_folder_path = folder_path.rstrip('/\\')
                output_path = clean_folder_path + "_folder.enc"
                
                try:
                    print("\nArchiving and encrypting folder...")
                    SecureVault.encrypt_folder(secret, folder_path, output_path)
                    print(f"[SUCCESS] Encrypted folder archive created: {output_path}")
                    
                    shred_choice = input("\nDo you want to SHRED the original unencrypted folder? (y/N): ").strip().lower()
                    if shred_choice == 'y':
                        print("Shredding original folder contents...")
                        SecureVault.shred_folder(folder_path)
                        print("[SUCCESS] Original folder and all internal files destroyed.")
                except Exception as e:
                    print(f"\n[ERROR] Folder encryption failed: {e}")

        elif choice == '6':
            print("\n--- DECRYPT FOLDER ---")
            file_path = input("Drag and drop folder .enc file here (or type path):\n> ").strip('"\' ')
            
            if not os.path.exists(file_path):
                print("\n[ERROR] Encrypted file does not exist!")
            else:
                secret = get_auth_secret(is_encryption=False)
                
                if file_path.endswith("_folder.enc"):
                    output_folder = file_path[:-11] + "_restored"
                elif file_path.endswith(".enc"):
                    output_folder = file_path[:-4] + "_restored"
                else:
                    output_folder = file_path + "_restored"
                    
                try:
                    print("\nDecrypting and extracting archive...")
                    SecureVault.decrypt_folder(secret, file_path, output_folder)
                    print(f"[SUCCESS] Restored folder contents to: {output_folder}")
                except InvalidTag:
                    print("\n[ERROR] Decryption failed! Incorrect password/keyfile or corrupted file.")
                except Exception as e:
                    print(f"\n[ERROR] Could not decrypt folder archive: {e}")

        elif choice == '7':
            print("\n--- STANDALONE SHREDDER ---")
            path = input("Drag and drop file or folder to destroy:\n> ").strip('"\' ')
            if not os.path.exists(path):
                print("\n[ERROR] Path does not exist!")
            else:
                confirm = input(f"WARNING: This will PERMANENTLY destroy '{path}'. Continue? (y/N): ").strip().lower()
                if confirm == 'y':
                    if os.path.isdir(path):
                        SecureVault.shred_folder(path)
                    else:
                        SecureVault.shred_file(path)
                    print("[SUCCESS] Target permanently destroyed.")

        elif choice == '8':
            print("\n--- HASH FILE ---")
            file_path = input("Drag and drop file here (or type path):\n> ").strip('"\' ')

            if not os.path.exists(file_path):
                print("\n[ERROR] File does not exist!")
            else:
                print("\nChoose a hashing method:")
                print("  [1] SHA-256")
                print("  [2] SHA-512")
                print("  [3] SHA-384")
                print("  [4] SHA-1")
                print("  [5] MD5")

                hash_choice = input("\nSelect option (1-5): ").strip()
                algorithms = {
                    '1': 'sha256',
                    '2': 'sha512',
                    '3': 'sha384',
                    '4': 'sha1',
                    '5': 'md5',
                }
                algorithm = algorithms.get(hash_choice)

                if algorithm is None:
                    print("\n[ERROR] Invalid hash method selection.")
                    continue

                try:
                    digest = SecureVault.hash_file(file_path, algorithm)
                    print("\n========================================")
                    print(f"{algorithm.upper()} HASH FOR '{file_path}':")
                    print(digest)
                    print("========================================")
                except ValueError as e:
                    print(f"\n[ERROR] {e}")
                except Exception as e:
                    print(f"\n[ERROR] Hashing failed: {e}")

        elif choice == '9':
            print("\nExiting Secure Vault. Stay safe!")
            break

        else:
            print("\nInvalid selection.")

        # Pause before looping back to the top
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
    print("\nThank you for using Secure Vault CLI. Goodbye!")