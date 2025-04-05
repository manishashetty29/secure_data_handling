# secure_data_handling


## Overview
This project demonstrates secure data handling through a simple graphical user interface (GUI) built using `tkinter` in Python. It incorporates encryption, decryption, digital signatures, and secure file storage. Additionally, password protection has been added for enhanced access control, making it suitable for educational demonstrations of information security principles.

---

## Features

### 1. **Secure Data Encryption**
- Uses `cryptography` library's Fernet (symmetric encryption).
- Ensures the confidentiality of the input data.

### 2. **Secure Data Decryption**
- Decryption is protected with a password (`ins123`) for simulated access control.
- Prompts the user to enter a password before decrypting.

### 3. **Digital Signature Creation**
- Uses `rsa` library to digitally sign the input data.
- Signing is also protected with a password.

### 4. **Digital Signature Verification**
- Validates if the input data matches the digital signature.
- Helps simulate data authenticity and integrity checks.

### 5. **Save to File**
- The user can save encrypted data to a `.enc` file using a GUI file dialog.

### 6. **Access Control**
- Simple password authentication added for sensitive operations like decryption and signing.

---

## Code Explanation & Logic

### Libraries Used:
- `tkinter`: For GUI creation.
- `cryptography.fernet`: For symmetric encryption and decryption.
- `rsa`: For creating and verifying digital signatures.
- `tkinter.simpledialog`: For password input prompts.

### Key Components:

#### 1. **Key Generation**
```python
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)
(pub_key, priv_key) = rsa.newkeys(512)
```
- Fernet key is generated for AES-based encryption.
- RSA keys are generated for signing and verification.

#### 2. **Password Verification**
```python
def ask_password():
    pwd = simpledialog.askstring("Authentication", "Enter password to proceed:", show='*')
    ...
```
- Prompts the user for a password before allowing decryption or signing.

#### 3. **Encrypt Function**
```python
def encrypt_data():
    data = input_text.get("1.0", tk.END).strip()
    encrypted = fernet.encrypt(data.encode())
```
- Takes input from the text box and encrypts it using Fernet.

#### 4. **Decrypt Function (Password Protected)**
```python
def decrypt_data():
    if not ask_password(): return
    decrypted = fernet.decrypt(data.encode()).decode()
```
- Validates password before decrypting.
- Displays the decrypted content in the output box.

#### 5. **Sign Data (Password Protected)**
```python
def sign_data():
    if not ask_password(): return
    signature = rsa.sign(data.encode(), priv_key, 'SHA-1')
```
- Signs the data using RSA and outputs the hex signature.

#### 6. **Verify Signature**
```python
def verify_signature():
    signature = bytes.fromhex(output_text.get(...))
    rsa.verify(data.encode(), signature, pub_key)
```
- Compares the signature with the data to check authenticity.

#### 7. **Save to File**
```python
def save_to_file():
    with open(file_path, "w") as f:
        f.write(data)
```
- Lets user choose a file location and saves the encrypted output securely.

---

## GUI Structure
- Two text areas: one for input, one for output.
- Buttons for `Encrypt`, `Decrypt`, `Sign`, `Verify`, and `Save to File`.
- Organized using `tk.Frame` and `grid` layout.

---

## Example Usage
- Input: `Welcome to the world of cryptography`
- Encrypt → Output is an encrypted string.
- Save to File → Saves the encrypted string.
- Decrypt (with password) → Original message shown.
- Sign (with password) → Generates a signature.
- Verify → Confirms the signature is valid.

---

## Demo Video
You can view the execution of the GUI, features, and functionality in this screen recording:
### https://drive.google.com/file/d/1uFHg33PTPHRVtvR9mUw0gbvdLI-KBzvK/view?usp=sharing

---

## Password for Access
- Password used in this project for decryption and signing is: **`ins123`**

---

## Final Note
This project demonstrates essential principles of cryptography:
- Confidentiality (via encryption)
- Integrity & Authenticity (via digital signatures)
- Access control (via password protection)





