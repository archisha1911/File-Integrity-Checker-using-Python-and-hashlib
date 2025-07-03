# File-Integrity-Checker-using-Python-and-hashlib
# 🔐 File Integrity Checker – CODTECH Internship Task 1

This project is a **File Integrity Checker** developed in Python using the `hashlib` module. It checks whether a file has been modified by comparing its current hash with a previously saved hash.

---

## 📂 How It Works

1. Calculates SHA-256 hash of the file.
2. Saves it in `hash_database.txt` if it's new.
3. If already saved, compares current hash with stored one.
4. Alerts if the file has been altered.

---

## 🚀 Getting Started

### ✅ Requirements
- Python 3.x

### ▶️ Run the Program
```bash
python file_integrity_checker.py
