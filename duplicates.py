import os
import json
import random
import string

def remove_duplicates_from_file(path):
    """Load JSON list of {"password": ...}, remove duplicate password values, save, return (before, after)."""
    # Check if the file exists
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return 0, 0

    try:
        # Read the content of the file
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

            # Check if the file is empty
            if not content.strip():
                print(f"File {path} is empty.")
                return 0, 0

            # Handle broken JSON by adding missing commas or brackets
            content = content.replace("][", "],[")

            # Try to load the cleaned content as JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                print(f"Error loading JSON from file {path}: {e}")
                print("The file may be malformed. Skipping this file.")
                return 0, 0

    except Exception as e:
        print(f"Error reading {path}: {e}")
        return 0, 0

    # Remove duplicates from the password list
    seen = set()
    unique = []
    for entry in data:
        pwd = entry.get("password")
        if pwd and pwd not in seen:
            seen.add(pwd)
            unique.append(entry)

    # Save unique passwords back to the file
    with open(path, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)

    # Print the number of duplicates removed
    print(f"Processed {len(data)} entries. Removed {len(data) - len(unique)} duplicates.")
    return len(data), len(unique)

def load_and_fix_json(file_path):
    """Load a JSON file and fix any common issues with the format."""
    try:
        with open(file_path, 'r', encoding="utf-8") as file:
            content = file.read()
            # Fix broken JSON array format
            content = content.replace("][", "],[")
            # Ensure the entire content is wrapped in square brackets
            data = json.loads('[' + content + ']')
            return data
    except json.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
        return []

def process_passwords():
    """Process all the password files in the 'lists' folder."""
    folder_path = 'lists'  # Directory where the password files are stored
    os.makedirs(folder_path, exist_ok=True)

    # Get all JSON password files in the 'lists' directory
    password_files = [file for file in os.listdir(folder_path) if file.endswith('.json')]

    for password_file in password_files:
        file_path = os.path.join(folder_path, password_file)

        try:
            # Read and fix JSON format if necessary
            passwords = load_and_fix_json(file_path)

            if not passwords:
                print(f"Skipping file {password_file} due to invalid or empty content.")
                continue

            # Remove duplicates
            before, after = remove_duplicates_from_file(file_path)

            # Print the number of duplicates removed
            num_removed = before - after
            if num_removed > 0:
                print(f"Removed {num_removed} duplicate passwords from {password_file}")
            else:
                print(f"No duplicates found in {password_file}")

        except Exception as e:
            print(f"Error processing file {password_file}: {e}")

if __name__ == "__main__":
    # Start processing the password files
    process_passwords()
