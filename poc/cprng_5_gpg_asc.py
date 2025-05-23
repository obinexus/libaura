import zipfile
import hashlib
import argparse
import os
import subprocess

def compute_hash(file_path, hash_type="md5"):
    h = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def external_hash_check(file_path, hash_type):
    if hash_type == "md5":
        cmd = ["md5sum", file_path]
    elif hash_type == "sha256":
        cmd = ["sha256sum", file_path]
    else:
        print("Unsupported hash type for external check.")
        return None
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running external hash command: {e}"

def gpg_sign_file(file_path, signer_key=None):
    cmd = ["gpg", "--batch", "--yes", "--output", file_path + ".asc", "--armor", "--detach-sign"]
    if signer_key:
        cmd.extend(["--local-user", signer_key])
    cmd.append(file_path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"GPG signature created: {file_path}.asc")
        else:
            print(f"GPG signing failed: {result.stderr}")
    except Exception as e:
        print(f"Error during GPG signing: {e}")

def gpg_verify_signature(sig_file):
    try:
        result = subprocess.run(["gpg", "--verify", sig_file], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✔️ Signature verified: {sig_file}")
        else:
            print(f"❌ Signature verification failed: {result.stderr}")
    except Exception as e:
        print(f"Error verifying signature: {e}")

def derive_zip_structure(zipfile_path):
    structure = []
    with zipfile.ZipFile(zipfile_path, 'r') as zip_ref:
        for zip_info in zip_ref.infolist():
            structure.append({
                'filename': zip_info.filename,
                'compressed_size': zip_info.compress_size,
                'uncompressed_size': zip_info.file_size,
            })
    return structure

def verify_zip_integrity(zipfile_path):
    results = []
    with zipfile.ZipFile(zipfile_path, 'r') as zip_ref:
        for zip_info in zip_ref.infolist():
            try:
                data = zip_ref.read(zip_info.filename)
                valid = len(data) == zip_info.file_size
                results.append({
                    'filename': zip_info.filename,
                    'expected_size': zip_info.file_size,
                    'actual_size': len(data),
                    'integrity_check_passed': valid
                })
            except Exception as e:
                results.append({
                    'filename': zip_info.filename,
                    'expected_size': zip_info.file_size,
                    'actual_size': None,
                    'integrity_check_passed': False,
                    'error': str(e)
                })
    return results

def write_signature_file(hash_value, target_dir, hash_type, signer_key=None):
    sig_path = os.path.join(target_dir, f"archive_signature.{hash_type}.sig")
    with open(sig_path, 'w') as f:
        f.write(f"{hash_type.upper()} Hash: {hash_value}\n")
    print(f"Signature file written to: {sig_path}")
    gpg_sign_file(sig_path, signer_key)

def main():
    parser = argparse.ArgumentParser(description="Verify ZIP file structure, compute hash, sign, and verify .sig")
    parser.add_argument("zipfile_path", help="Path to the ZIP file")
    parser.add_argument("--hash-type", default="md5", choices=["md5", "sha256"], help="Hash function to use")
    parser.add_argument("--verify-hash", help="Hash string to verify against")
    parser.add_argument("--target-dir", help="Directory to save or extract zip contents to", default=None)
    parser.add_argument("--sign-with", help="GPG key ID or email to sign the .sig file")
    parser.add_argument("--verify-sig", help="Path to .asc signature file to verify")
    args = parser.parse_args()

    if args.verify_sig:
        gpg_verify_signature(args.verify_sig)
        return

    print("Deriving ZIP structure...")
    structure = derive_zip_structure(args.zipfile_path)
    for entry in structure:
        print(entry)

    print("\nVerifying ZIP contents...")
    integrity_results = verify_zip_integrity(args.zipfile_path)
    for result in integrity_results:
        print(result)

    print("\nComputing hash (internal Python)...")
    computed_hash = compute_hash(args.zipfile_path, args.hash_type)
    print(f"Computed {args.hash_type.upper()} Hash: {computed_hash}")

    print("\nComputing hash (external system command)...")
    external_result = external_hash_check(args.zipfile_path, args.hash_type)
    if external_result:
        print(f"External hash output: {external_result}")

    if args.verify_hash:
        if computed_hash == args.verify_hash:
            print("✔️ Hash verification passed.")
        else:
            print("❌ Hash verification failed.")

    if args.target_dir:
        print(f"\nExtracting ZIP to: {args.target_dir}")
        os.makedirs(args.target_dir, exist_ok=True)
        with zipfile.ZipFile(args.zipfile_path, 'r') as zip_ref:
            zip_ref.extractall(args.target_dir)
        print("Extraction complete.")
        write_signature_file(computed_hash, args.target_dir, args.hash_type, signer_key=args.sign_with)

if __name__ == "__main__":
    main()
