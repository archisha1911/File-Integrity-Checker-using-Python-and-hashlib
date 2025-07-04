import hashlib
import os

def calculate_file_hash(filepath, algorithm='sha256'):
    """
    Calculates the hash of a file using the specified algorithm.
    Args:
        filepath (str): The path to the file.
        algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').
    Returns:
        str: The hexadecimal representation of the file's hash, or None if the file is not found.
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found at {filepath}")
        return None

    hash_func = getattr(hashlib, algorithm, None)
    if hash_func is None:
        print(f"Error: Hashing algorithm '{algorithm}' not supported.")
        return None

    hasher = hash_func()
    try:
        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {filepath}: {e}")
        return None

def store_file_hash(filepath, hash_value, hash_storage_file='file_hashes.txt'):
    """
    Stores the file path and its hash value in a text file.
    Args:
        filepath (str): The path to the file.
        hash_value (str): The calculated hash value of the file.
        hash_storage_file (str): The name of the file to store hashes.
    """
    with open(hash_storage_file, 'a') as f:
        f.write(f"{filepath},{hash_value}\n")
    print(f"Hash for {filepath} stored.")

def load_stored_hashes(hash_storage_file='file_hashes.txt'):
    """
    Loads stored file hashes from a text file.
    Args:
        hash_storage_file (str): The name of the file where hashes are stored.
    Returns:
        dict: A dictionary mapping file paths to their stored hash values.
    """
    stored_hashes = {}
    if os.path.exists(hash_storage_file):
        with open(hash_storage_file, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    stored_hashes[parts[0]] = parts[1]
    return stored_hashes

def check_file_integrity(filepath, stored_hashes, algorithm='sha256'):
    """
    Checks the integrity of a file by comparing its current hash with a stored hash.
    Args:
        filepath (str): The path to the file.
        stored_hashes (dict): A dictionary of previously stored hashes.
        algorithm (str): The hashing algorithm used for comparison.
    Returns:
        bool: True if the file's current hash matches the stored hash, False otherwise.
    """
    current_hash = calculate_file_hash(filepath, algorithm)
    if current_hash is None:
        return False

    if filepath in stored_hashes:
        stored_hash = stored_hashes[filepath]
        if current_hash == stored_hash:
            print(f"Integrity check passed for {filepath}. No changes detected.")
            return True
        else:
            print(f"Integrity check failed for {filepath}. File has been modified!")
            print(f"  Stored hash: {stored_hash}")
            print(f"  Current hash: {current_hash}")
            return False
    else:
        print(f"No stored hash found for {filepath}. Consider storing its initial hash.")
        return False

if __name__ == "__main__":
    # --- Example Usage ---

    # Define a dummy file for testing
    test_file_name = "my_important_file.txt"
    hash_storage_file_name = "file_hashes.txt"

    # Create a dummy file if it doesn't exist
    if not os.path.exists(test_file_name):
        with open(test_file_name, 'w') as f:
            f.write("This is the original content of my important file.\n")
        print(f"Created a dummy file: {test_file_name}")

    # 1. Calculate and store the initial hash of the file
    print("\n--- Initial Hash Calculation and Storage ---")
    initial_hash = calculate_file_hash(test_file_name)
    if initial_hash:
        store_file_hash(test_file_name, initial_hash, hash_storage_file_name)

    # 2. Load stored hashes
    print("\n--- Loading Stored Hashes ---")
    my_stored_hashes = load_stored_hashes(hash_storage_file_name)
    print(f"Loaded hashes: {my_stored_hashes}")

    # 3. Check integrity for the first time (should pass if stored)
    print("\n--- First Integrity Check ---")
    check_file_integrity(test_file_name, my_stored_hashes)

    # 4. Simulate a change in the file
    print("\n--- Simulating File Modification ---")
    with open(test_file_name, 'a') as f:
        f.write("Appending some new content to simulate a change.\n")
    print(f"Modified {test_file_name}")

    # 5. Check integrity again (should fail)
    print("\n--- Second Integrity Check (after modification) ---")
    check_file_integrity(test_file_name, my_stored_hashes)

    # 6. Re-calculate and store the new hash if desired (e.g., after a legitimate update)
    print("\n--- Re-calculating and Storing New Hash ---")
    new_hash = calculate_file_hash(test_file_name)
    if new_hash:
        # Update the stored hash for this file
        # This overwrites the old entry for test_file_name in our simple storage
        # For a more robust solution, you'd manage this dictionary and rewrite the file_hashes.txt
        # or use a proper database.
        with open(hash_storage_file_name, 'w') as f: # Simple overwrite for demonstration
             f.write(f"{test_file_name},{new_hash}\n")
        print(f"New hash for {test_file_name} stored.")
        my_stored_hashes = load_stored_hashes(hash_storage_file_name) # Reload to reflect changes

    # 7. Check integrity one more time (should pass with the new stored hash)
    print("\n--- Third Integrity Check (after storing new hash) ---")
    check_file_integrity(test_file_name, my_stored_hashes)

    # Clean up dummy files (optional)
    # os.remove(test_file_name)
    # os.remove(hash_storage_file_name)
    # print(f"\nCleaned up {test_file_name} and {hash_storage_file_name}")