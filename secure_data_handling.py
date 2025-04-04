import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.fernet import Fernet
import rsa

# Fixed password for access control
SECURE_PASSWORD = "ins123"

# Generate keys once
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

(pub_key, priv_key) = rsa.newkeys(512)

# GUI setup
window = tk.Tk()
window.title("Secure Data Handling")
window.geometry("600x500")

# Input textbox
input_label = tk.Label(window, text="Enter Data:")
input_label.pack()
input_text = tk.Text(window, height=5)
input_text.pack()

# Output textbox
output_label = tk.Label(window, text="Output:")
output_label.pack()
output_text = tk.Text(window, height=10)
output_text.pack()

# Password prompt
def ask_password():
    pwd = simpledialog.askstring("Authentication", "Enter password to proceed:", show='*')
    if pwd == SECURE_PASSWORD:
        return True
    else:
        messagebox.showerror("Access Denied", "Invalid password.")
        return False

# Encrypt function
def encrypt_data():
    data = input_text.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("Empty", "Please enter some text.")
        return
    encrypted = fernet.encrypt(data.encode())
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted)

# Decrypt function (with password check)
def decrypt_data():
    if not ask_password():
        return
    data = input_text.get("1.0", tk.END).strip()
    try:
        decrypted = fernet.decrypt(data.encode()).decode()
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
    except:
        messagebox.showerror("Error", "Decryption failed. Make sure it's valid encrypted data.")

# Sign function (with password check)
def sign_data():
    if not ask_password():
        return
    data = input_text.get("1.0", tk.END).strip()
    signature = rsa.sign(data.encode(), priv_key, 'SHA-1')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Signature:\n{signature.hex()}")

# Verify signature
def verify_signature():
    try:
        data = input_text.get("1.0", tk.END).strip()
        signature = bytes.fromhex(output_text.get("1.0", tk.END).strip().replace("Signature:\n", ""))
        rsa.verify(data.encode(), signature, pub_key)
        messagebox.showinfo("Valid", "Signature is valid.")
    except:
        messagebox.showerror("Invalid", "Signature is not valid.")

# Save encrypted data to file
def save_to_file():
    data = output_text.get("1.0", tk.END).strip()
    if not data:
        messagebox.showerror("Error", "No data to save!")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".enc",
        filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")],
        title="Save Encrypted File"
    )

    if file_path:
        try:
            with open(file_path, "w") as f:
                f.write(data)
            messagebox.showinfo("Success", f"Encrypted data saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file:\n{str(e)}")

# Buttons
btn_frame = tk.Frame(window)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Encrypt", command=encrypt_data).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Decrypt", command=decrypt_data).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Sign", command=sign_data).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Verify", command=verify_signature).grid(row=0, column=3, padx=5)
tk.Button(btn_frame, text="Save to File", command=save_to_file).grid(row=0, column=4, padx=5)

window.mainloop()

