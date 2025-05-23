import zipfile
import hashlib
import argparse
import os

def compute_hash(file_path, hash_type="md5"):
    h = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

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

def main():
    parser = argparse.ArgumentParser(description="Verify ZIP file structure and hash")
    parser.add_argument("zipfile_path", help="Path to the ZIP file")
    parser.add_argument("--hash-type", default="md5", choices=["md5", "sha256"], help="Hash function to use")
    parser.add_argument("--verify-hash", help="Hash string to verify against")
    parser.add_argument("--target-dir", help="Directory to save or extract zip contents to", default=None)
    args = parser.parse_args()

    print("Deriving ZIP structure...")
    structure = derive_zip_structure(args.zipfile_path)
    for entry in structure:
        print(entry)

    print("\nVerifying ZIP contents...")
    integrity_results = verify_zip_integrity(args.zipfile_path)
    for result in integrity_results:
        print(result)

    print("\nComputing hash...")
    computed_hash = compute_hash(args.zipfile_path, args.hash_type)
    print(f"Computed {args.hash_type.upper()} Hash: {computed_hash}")

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

if __name__ == "__main__":
    main()
