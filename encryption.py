# # # # # import tkinter as tk
# # # # # from tkinter import filedialog, messagebox, ttk
# # # # # from cryptography.hazmat.primitives.asymmetric import rsa, padding
# # # # # from cryptography.hazmat.primitives import hashes
# # # # # from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# # # # # import os
# # # # # import base64


# # # # # class CryptographyApp:
# # # # #     def __init__(self, root):
# # # # #         self.root = root
# # # # #         self.root.title("ابزار رمزنگاری")

# # # # #         # Main container
# # # # #         self.container = tk.Frame(root, padx=10, pady=10)
# # # # #         self.container.pack(fill="both", expand=True)

# # # # #         # Section: Algorithm Selection
# # # # #         self.algorithm_frame = tk.LabelFrame(self.container, text="انتخاب الگوریتم", padx=10, pady=10)
# # # # #         self.algorithm_frame.pack(fill="x", pady=5)

# # # # #         tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # # #         self.crypto_type = tk.StringVar(value="متقارن")
# # # # #         self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
# # # # #         self.symmetric_radio.grid(row=0, column=1, sticky="w")
# # # # #         self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
# # # # #         self.asymmetric_radio.grid(row=0, column=2, sticky="w")
# # # # #         self.hash_radio = tk.Radiobutton(self.algorithm_frame, text="هشینگ", variable=self.crypto_type, value="هشینگ")
# # # # #         self.hash_radio.grid(row=0, column=3, sticky="w")

# # # # #         tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # # # #         self.algorithm = ttk.Combobox(
# # # # #             self.algorithm_frame, values=["AES", "RSA", "SHA-256", "SHA-3"], state="readonly"
# # # # #         )
# # # # #         self.algorithm.grid(row=1, column=1, sticky="w")
# # # # #         self.algorithm.current(0)

# # # # #         # Section: File/Data Input
# # # # #         self.input_frame = tk.LabelFrame(self.container, text="ورودی فایل/داده", padx=10, pady=10)
# # # # #         self.input_frame.pack(fill="x", pady=5)

# # # # #         tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
# # # # #         self.file_path = tk.StringVar()
# # # # #         self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
# # # # #         self.file_entry.grid(row=0, column=1, sticky="w")
# # # # #         self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
# # # # #         self.browse_button.grid(row=0, column=2, sticky="w")

# # # # #         tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # # # #         self.text_area = tk.Text(self.input_frame, height=5, width=50)
# # # # #         self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

# # # # #         # Section: Output Box
# # # # #         self.output_frame = tk.LabelFrame(self.container, text="خروجی", padx=10, pady=10)
# # # # #         self.output_frame.pack(fill="x", pady=5)

# # # # #         tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # # # #         self.output_text = tk.Text(self.output_frame, height=5, width=50)
# # # # #         self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # # # #         self.output_text.config(state="disabled")  # Make it read-only

# # # # #         self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
# # # # #         self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

# # # # #         # Section: Action Buttons
# # # # #         self.action_frame = tk.Frame(self.container, padx=10, pady=10)
# # # # #         self.action_frame.pack(fill="x", pady=5)

# # # # #         self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
# # # # #         self.encrypt_button.pack(side="left", padx=5)

# # # # #         self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
# # # # #         self.hash_button.pack(side="left", padx=5)

# # # # #         # Generate RSA keys (for asymmetric encryption)
# # # # #         self.private_key, self.public_key = self.generate_rsa_keys()

# # # # #     def browse_file(self):
# # # # #         file_path = filedialog.askopenfilename()
# # # # #         if file_path:
# # # # #             self.file_path.set(file_path)

# # # # #     def encrypt_data(self):
# # # # #         algorithm = self.algorithm.get()
# # # # #         if algorithm == "AES":
# # # # #             self.aes_encrypt()
# # # # #         elif algorithm == "RSA":
# # # # #             self.rsa_encrypt()
# # # # #         else:
# # # # #             messagebox.showerror("خطا", f"رمزگذاری برای {algorithm} پشتیبانی نمی‌شود.")

# # # # #     def generate_hash(self):
# # # # #         algorithm = self.algorithm.get()
# # # # #         if algorithm in ["SHA-256", "SHA-3"]:
# # # # #             data = self.get_input_data()
# # # # #             if not data:
# # # # #                 messagebox.showerror("خطا", "لطفاً متنی برای هش کردن وارد کنید.")
# # # # #                 return
# # # # #             if algorithm == "SHA-256":
# # # # #                 digest = hashes.Hash(hashes.SHA256())
# # # # #             elif algorithm == "SHA-3":
# # # # #                 digest = hashes.Hash(hashes.SHA3_256())
# # # # #             digest.update(data.encode())
# # # # #             hashed_data = digest.finalize()
# # # # #             self.show_output(hashed_data.hex())
# # # # #         else:
# # # # #             messagebox.showerror("خطا", f"هشینگ برای {algorithm} پشتیبانی نمی‌شود.")

# # # # #     def aes_encrypt(self):
# # # # #         key = os.urandom(32)  # Generate a random 256-bit key
# # # # #         iv = os.urandom(16)   # Generate a random IV
# # # # #         data = self.get_input_data()
# # # # #         if not data:
# # # # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # # # #             return
# # # # #         cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
# # # # #         encryptor = cipher.encryptor()
# # # # #         ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
# # # # #         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
# # # # #         self.show_output(encrypted_base64)

# # # # #     def rsa_encrypt(self):
# # # # #         data = self.get_input_data()
# # # # #         if not data:
# # # # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # # # #             return
# # # # #         ciphertext = self.public_key.encrypt(
# # # # #             data.encode(),
# # # # #             padding.OAEP(
# # # # #                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
# # # # #                 algorithm=hashes.SHA256(),
# # # # #                 label=None
# # # # #             )
# # # # #         )
# # # # #         encrypted_base64 = base64.b64encode(ciphertext).decode()
# # # # #         self.show_output(encrypted_base64)

# # # # #     def generate_rsa_keys(self):
# # # # #         private_key = rsa.generate_private_key(
# # # # #             public_exponent=65537,
# # # # #             key_size=2048,
# # # # #         )
# # # # #         public_key = private_key.public_key()
# # # # #         return private_key, public_key

# # # # #     def get_input_data(self):
# # # # #         if self.file_path.get():
# # # # #             try:
# # # # #                 with open(self.file_path.get(), "r") as file:
# # # # #                     return file.read()
# # # # #             except Exception as e:
# # # # #                 messagebox.showerror("خطا", f"خطا در خواندن فایل: {e}")
# # # # #                 return None
# # # # #         else:
# # # # #             return self.text_area.get("1.0", tk.END).strip()

# # # # #     def show_output(self, output):
# # # # #         self.output_text.config(state="normal")
# # # # #         self.output_text.delete("1.0", tk.END)
# # # # #         self.output_text.insert("1.0", output)
# # # # #         self.output_text.config(state="disabled")

# # # # #     def copy_output(self):
# # # # #         self.root.clipboard_clear()
# # # # #         self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
# # # # #         self.root.update()
# # # # #         messagebox.showinfo("کپی شد", "خروجی کپی شد!")


# # # # # if __name__ == "__main__":
# # # # #     root = tk.Tk()
# # # # #     app = CryptographyApp(root)
# # # # #     root.mainloop()

























# # # # import tkinter as tk
# # # # from tkinter import filedialog, messagebox, ttk
# # # # from Crypto.Cipher import AES, DES3, PKCS1_OAEP
# # # # from Crypto.PublicKey import RSA
# # # # from Crypto.Hash import SHA256, SHA3_256
# # # # from Crypto.Random import get_random_bytes
# # # # import base64
# # # # import itertools
# # # # import string
# # # # from collections import defaultdict
# # # # import threading

# # # # class CryptographyApp:
# # # #     def __init__(self, root):
# # # #         self.root = root
# # # #         self.root.title("ابزار رمزنگاری و شکستن رمز")

# # # #         # Main container
# # # #         self.container = tk.Frame(root, padx=10, pady=10)
# # # #         self.container.pack(fill="both", expand=True)

# # # #         # Create the tab control
# # # #         self.tab_control = ttk.Notebook(self.container)

# # # #         # Create tabs
# # # #         self.encryption_tab = ttk.Frame(self.tab_control)
# # # #         self.breaking_tab = ttk.Frame(self.tab_control)

# # # #         self.tab_control.add(self.encryption_tab, text="رمزنگاری و رمزگشایی")
# # # #         self.tab_control.add(self.breaking_tab, text="شکستن رمز")

# # # #         self.tab_control.pack(expand=1, fill="both")

# # # #         # Setup encryption tab
# # # #         self.setup_encryption_tab()

# # # #         # Setup breaking tab
# # # #         self.setup_breaking_tab()

# # # #         # Generate RSA keys (for asymmetric encryption)
# # # #         self.private_key, self.public_key = self.generate_rsa_keys()

# # # #         # Variable to store hashed value and keys
# # # #         self.hashed_value = None
# # # #         self.aes_key = None
# # # #         self.des_key = None
# # # #         self.dictionary = []  # For storing dictionary words
# # # #         self.rainbow_table = defaultdict(list)  # For storing rainbow table entries

# # # #     def setup_encryption_tab(self):
# # # #         # Section: Algorithm Selection
# # # #         self.algorithm_frame = tk.LabelFrame(self.encryption_tab, text="انتخاب الگوریتم", padx=10, pady=10)
# # # #         self.algorithm_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.crypto_type = tk.StringVar(value="متقارن")
# # # #         self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
# # # #         self.symmetric_radio.grid(row=0, column=1, sticky="w")
# # # #         self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
# # # #         self.asymmetric_radio.grid(row=0, column=2, sticky="w")

# # # #         tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # # #         self.algorithm = ttk.Combobox(
# # # #             self.algorithm_frame, values=[
# # # #                 "AES", "3DES", "RSA", "SHA-256", "SHA-3"
# # # #             ], state="readonly"
# # # #         )
# # # #         self.algorithm.grid(row=1, column=1, sticky="w")
# # # #         self.algorithm.current(0)

# # # #         # Section: File/Data Input
# # # #         self.input_frame = tk.LabelFrame(self.encryption_tab, text="ورودی فایل/داده", padx=10, pady=10)
# # # #         self.input_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.file_path = tk.StringVar()
# # # #         self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
# # # #         self.file_entry.grid(row=0, column=1, sticky="w")
# # # #         self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
# # # #         self.browse_button.grid(row=0, column=2, sticky="w")

# # # #         tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # # #         self.text_area = tk.Text(self.input_frame, height=5, width=50)
# # # #         self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

# # # #         # Section: Output Box
# # # #         self.output_frame = tk.LabelFrame(self.encryption_tab, text="خروجی", padx=10, pady=10)
# # # #         self.output_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.output_text = tk.Text(self.output_frame, height=5, width=50)
# # # #         self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # # #         self.output_text.config(state="disabled")  # Make it read-only

# # # #         self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
# # # #         self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         # Section: Action Buttons
# # # #         self.action_frame = tk.Frame(self.encryption_tab, padx=10, pady=10)
# # # #         self.action_frame.pack(fill="x", pady=5)

# # # #         self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
# # # #         self.encrypt_button.pack(side="left", padx=5)

# # # #         self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
# # # #         self.hash_button.pack(side="left", padx=5)
# # # #         def setup_breaking_tab(self):
# # # #         # ایجاد تب برای شکستن هش
# # # #             self.break_algorithm_frame = ttk.LabelFrame(self.breaking_tab, text="شکستن هش", padding=(10, 10))
# # # #             self.break_algorithm_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.break_algorithm_frame, text="متن هش شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.hash_input = tk.Entry(self.break_algorithm_frame, width=40)
# # # #         self.hash_input.grid(row=0, column=1, sticky="w")

# # # #         # تب‌های جدید
# # # #         self.tab_control = ttk.Notebook(self.breaking_tab)

# # # #         # تب Rainbow Tables
# # # #         self.rainbow_tab = ttk.Frame(self.tab_control)
# # # #         self.tab_control.add(self.rainbow_tab, text="Rainbow Tables")
# # # #         self.setup_rainbow_tab()

# # # #         # تب Timing Attacks
# # # #         self.timing_tab = ttk.Frame(self.tab_control)
# # # #         self.tab_control.add(self.timing_tab, text="Timing Attacks")
# # # #         self.setup_timing_tab()

# # # #         # تب Side-Channel Attacks
# # # #         self.side_channel_tab = ttk.Frame(self.tab_control)
# # # #         self.tab_control.add(self.side_channel_tab, text="Side-Channel Attacks")
# # # #         self.setup_side_channel_tab()

# # # #         # تب Key Recovery
# # # #         self.key_recovery_tab = ttk.Frame(self.tab_control)
# # # #         self.tab_control.add(self.key_recovery_tab, text="Key Recovery")
# # # #         self.setup_key_recovery_tab()

# # # #         # تب Chosen Ciphertext Attack
# # # #         self.cca_tab = ttk.Frame(self.tab_control)
# # # #         self.tab_control.add(self.cca_tab, text="Chosen Ciphertext Attack")
# # # #         self.setup_cca_tab()

# # # #         self.tab_control.pack(expand=1, fill="both")

# # # #     def setup_rainbow_tab(self):
# # # #         # پیاده‌سازی رابط کاربری برای Rainbow Tables
# # # #         tk.Label(self.rainbow_tab, text="متن هش را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.rainbow_hash_input = tk.Entry(self.rainbow_tab, width=40)
# # # #         self.rainbow_hash_input.grid(row=0, column=1, sticky="w")

# # # #         self.rainbow_crack_button = tk.Button(self.rainbow_tab, text="شکستن هش با Rainbow Tables", command=self.crack_with_rainbow_tables)
# # # #         self.rainbow_crack_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         self.rainbow_output_text = tk.Text(self.rainbow_tab, height=5, width=50)
# # # #         self.rainbow_output_text.grid(row=2, column=0, columnspan=2, pady=5)

# # # #     def setup_timing_tab(self):
# # # #         # پیاده‌سازی رابط کاربری برای Timing Attacks
# # # #         tk.Label(self.timing_tab, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.timing_input = tk.Entry(self.timing_tab, width=40)
# # # #         self.timing_input.grid(row=0, column=1, sticky="w")

# # # #         self.timing_attack_button = tk.Button(self.timing_tab, text="اجرای حمله زمانی", command=self.run_timing_attack)
# # # #         self.timing_attack_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         self.timing_output_text = tk.Text(self.timing_tab, height=5, width=50)
# # # #         self.timing_output_text.grid(row=2, column=0, columnspan=2, pady=5)

# # # #     def setup_side_channel_tab(self):
# # # #         # پیاده‌سازی رابط کاربری برای Side-Channel Attacks
# # # #         tk.Label(self.side_channel_tab, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.side_channel_input = tk.Entry(self.side_channel_tab, width=40)
# # # #         self.side_channel_input.grid(row=0, column=1, sticky="w")

# # # #         self.side_channel_attack_button = tk.Button(self.side_channel_tab, text="اجرای حمله جانبی", command=self.run_side_channel_attack)
# # # #         self.side_channel_attack_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         self.side_channel_output_text = tk.Text(self.side_channel_tab, height=5, width=50)
# # # #         self.side_channel_output_text.grid(row=2, column=0, columnspan=2, pady=5)

# # # #     def setup_key_recovery_tab(self):
# # # #         # پیاده‌سازی رابط کاربری برای Key Recovery
# # # #         tk.Label(self.key_recovery_tab, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.key_recovery_input = tk.Entry(self.key_recovery_tab, width=40)
# # # #         self.key_recovery_input.grid(row=0, column=1, sticky="w")

# # # #         self.key_recovery_button = tk.Button(self.key_recovery_tab, text="اجرای حمله بازیابی کلید", command=self.run_key_recovery_attack)
# # # #         self.key_recovery_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         self.key_recovery_output_text = tk.Text(self.key_recovery_tab, height=5, width=50)
# # # #         self.key_recovery_output_text.grid(row=2, column=0, columnspan=2, pady=5)

# # # #     def setup_cca_tab(self):
# # # #         # پیاده‌سازی رابط کاربری برای Chosen Ciphertext Attack
# # # #         tk.Label(self.cca_tab, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.cca_input = tk.Entry(self.cca_tab, width=40)
# # # #         self.cca_input.grid(row=0, column=1, sticky="w")

# # # #         self.cca_attack_button = tk.Button(self.cca_tab, text="اجرای حمله CCA", command=self.run_cca_attack)
# # # #         self.cca_attack_button.grid(row=1, column=1, pady=5, sticky="e")

# # # #         self.cca_output_text = tk.Text(self.cca_tab, height=5, width=50)
# # # #         self.cca_output_text.grid(row=2, column=0, columnspan=2, pady=5)

# # # #     # متدهای مربوط به هر حمله باید در اینجا پیاده‌سازی شوند

# # # #     def setup_breaking_tab(self):
# # # #         # Section: Break Algorithm
# # # #         self.break_algorithm_frame = tk.LabelFrame(self.breaking_tab, text="شکستن رمز", padx=10, pady=10)
# # # #         self.break_algorithm_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.break_algorithm_frame, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.break_input_text = tk.Text(self.break_algorithm_frame, height=5, width=50)
# # # #         self.break_input_text.grid(row=0, column=1, columnspan=2, sticky="w")

# # # #         tk.Label(self.break_algorithm_frame, text="الگوریتم را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # # #         self.break_algorithm = ttk.Combobox(
# # # #             self.break_algorithm_frame, values=["AES", "3DES", "RSA"], state="readonly"
# # # #         )
# # # #         self.break_algorithm.grid(row=1, column=1, sticky="w")
# # # #         self.break_algorithm.current(0)

# # # #         self.break_button = tk.Button(self.break_algorithm_frame, text="شکستن رمز", command=self.break_data)
# # # #         self.break_button.grid(row=2, column=1, pady=5, sticky="e")

# # # #         # Section: Hash Breaking
# # # #         self.hash_frame = tk.LabelFrame(self.breaking_tab, text="شکستن هش", padx=10, pady=10)
# # # #         self.hash_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.hash_frame, text="متن هش شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.hash_input = tk.Entry(self.hash_frame, width=40)
# # # #         self.hash_input.grid(row=0, column=1, sticky="w")

# # # #         tk.Label(self.hash_frame, text="متن برای مقایسه:").grid(row=1, column=0, sticky="w", pady=5)
# # # #         self.compare_input = tk.Entry(self.hash_frame, width=40)
# # # #         self.compare_input.grid(row=1, column=1, sticky="w")

# # # #         self.check_hash_button = tk.Button(self.hash_frame, text="بررسی هش", command=self.check_hash)
# # # #         self.check_hash_button.grid(row=2, column=1, pady=5, sticky="e")

# # # #         self.crack_hash_button = tk.Button(self.hash_frame, text="شکستن هش با دیکشنری", command=self.crack_hash_with_dictionary)
# # # #         self.crack_hash_button.grid(row=3, column=1, pady=5, sticky="e")

# # # #         self.brute_force_button = tk.Button(self.hash_frame, text="حمله Brute Force", command=self.run_brute_force_attack)
# # # #         self.brute_force_button.grid(row=4, column=1, pady=5, sticky="e")

# # # #         # Section: Output for Hash Breaking
# # # #         self.hash_output_frame = tk.LabelFrame(self.breaking_tab, text="نتیجه", padx=10, pady=10)
# # # #         self.hash_output_frame.pack(fill="x", pady=5)

# # # #         tk.Label(self.hash_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # # #         self.hash_output_text = tk.Text(self.hash_output_frame, height=5, width=50)
# # # #         self.hash_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # # #         self.hash_output_text.config(state="disabled")  # Make it read-only

# # # #         # Section: Load Dictionary
# # # #         self.load_dictionary_button = tk.Button(self.hash_frame, text="بارگذاری دیکشنری", command=self.load_dictionary)
# # # #         self.load_dictionary_button.grid(row=5, column=1, pady=5, sticky="e")

# # # #     def browse_file(self):
# # # #         file_path = filedialog.askopenfilename()
# # # #         if file_path:
# # # #             self.file_path.set(file_path)

# # # #     def load_dictionary(self):
# # # #         file_path = filedialog.askopenfilename()
# # # #         if file_path:
# # # #             try:
# # # #                 with open(file_path, 'r') as file:
# # # #                     self.dictionary = [line.strip() for line in file.readlines()]
# # # #                 messagebox.showinfo("موفقیت", "دیکشنری با موفقیت بارگذاری شد.")
# # # #                 print(f"Dictionaries loaded: {self.dictionary}")  # Debug statement
# # # #                 if not self.dictionary:
# # # #                     print("Warning: Dictionary is empty after loading.")
# # # #             except Exception as e:
# # # #                 messagebox.showerror("خطا", f"خطا در بارگذاری دیکشنری: {e}")
# # # #                 print(f"Error loading dictionary: {str(e)}")

# # # #     def encrypt_data(self):
# # # #         algorithm = self.algorithm.get()
# # # #         if algorithm == "AES":
# # # #             self.aes_encrypt()
# # # #         elif algorithm == "3DES":
# # # #             self.three_des_encrypt()
# # # #         elif algorithm == "RSA":
# # # #             self.rsa_encrypt()
# # # #         else:
# # # #             messagebox.showerror("خطا", f"رمزگذاری برای {algorithm} پشتیبانی نمی‌شود.")

# # # #     def generate_hash(self):
# # # #         algorithm = self.algorithm.get()
# # # #         data = self.get_input_data()
# # # #         if not data:
# # # #             messagebox.showerror("خطا", "لطفاً متنی برای هش کردن وارد کنید.")
# # # #             return
# # # #         if algorithm == "SHA-256":
# # # #             digest = SHA256.new()
# # # #         elif algorithm == "SHA-3":
# # # #             digest = SHA3_256.new()
# # # #         else:
# # # #             messagebox.showerror("خطا", f"هشینگ برای {algorithm} پشتیبانی نمی‌شود.")
# # # #             return
        
# # # #         digest.update(data.encode())
# # # #         self.hashed_value = digest.hexdigest()  # Store the hashed value
# # # #         self.show_output(self.hashed_value)
# # # #         self.populate_rainbow_table(data)  # Populate the rainbow table with the original data

# # # #     def populate_rainbow_table(self, original_data):
# # # #         # Add the original data and its hash to the rainbow table
# # # #         sha256_hash = SHA256.new(original_data.encode()).hexdigest()
# # # #         self.rainbow_table[sha256_hash].append(original_data)

# # # #     def check_hash(self):
# # # #         # Get the hashed value and comparison input
# # # #         hashed_value = self.hash_input.get().strip()
# # # #         comparison_input = self.compare_input.get().strip()

# # # #         if not hashed_value or not comparison_input:
# # # #             messagebox.showerror("خطا", "لطفاً هر دو متن را وارد کنید.")
# # # #             return

# # # #         # Check if the input matches the hash
# # # #         sha256_hash = SHA256.new(comparison_input.encode()).hexdigest()

# # # #         if sha256_hash == hashed_value:
# # # #             self.show_hash_break_output("متن صحیح است!")
# # # #         else:
# # # #             self.show_hash_break_output("متن صحیح نیست!")

# # # #     def crack_hash_with_dictionary(self):
# # # #         hashed_value = self.hash_input.get().strip()
# # # #         if not hashed_value:
# # # #             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
# # # #             return
        
# # # #         if not self.dictionary:
# # # #             messagebox.showerror("خطا", "لطفاً ابتدا دیکشنری را بارگذاری کنید.")
# # # #             return

# # # #         found = False
# # # #         for word in self.dictionary:
# # # #             sha256_hash = SHA256.new(word.encode()).hexdigest()
# # # #             if sha256_hash == hashed_value:
# # # #                 self.show_hash_break_output(f"کلمه اصلی: {word}")
# # # #                 found = True
# # # #                 break
        
# # # #         if not found:
# # # #             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

# # # #     def run_brute_force_attack(self):
# # # #         hashed_value = self.hash_input.get().strip()
# # # #         if not hashed_value:
# # # #             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
# # # #             return

# # # #         # Start the brute force attack in a separate thread
# # # #         threading.Thread(target=self.brute_force_attack, args=(hashed_value,)).start()

# # # #     def brute_force_attack(self, hashed_value):
# # # #         characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
# # # #         found = False
# # # #         for length in range(1, 6):  # Try lengths from 1 to 5
# # # #             for attempt in itertools.product(characters, repeat=length):
# # # #                 password = ''.join(attempt)
# # # #                 sha256_hash = SHA256.new(password.encode()).hexdigest()
# # # #                 if sha256_hash == hashed_value:
# # # #                     self.show_hash_break_output(f"کلمه اصلی: {password}")
# # # #                     found = True
# # # #                     break  # Exit the loop if the password is found
# # # #             if found:
# # # #                 break  # Exit outer loop if the password is found
# # # #         if not found:
# # # #             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

# # # #     def rainbow_table_attack(self, hashed_value):
# # # #         # Check if the hashed value exists in the rainbow table
# # # #         if hashed_value in self.rainbow_table:
# # # #             return self.rainbow_table[hashed_value]
# # # #         return None

# # # #     def show_hash_break_output(self, output):
# # # #         self.hash_output_text.config(state="normal")
# # # #         self.hash_output_text.delete("1.0", tk.END)
# # # #         self.hash_output_text.insert("1.0", output)
# # # #         self.hash_output_text.config(state="disabled")

# # # #     def break_data(self):
# # # #         algorithm = self.break_algorithm.get()
# # # #         encrypted_text = self.break_input_text.get("1.0", tk.END).strip()
# # # #         try:
# # # #             if algorithm == "AES":
# # # #                 self.aes_decrypt(encrypted_text)
# # # #             elif algorithm == "3DES":
# # # #                 self.three_des_decrypt(encrypted_text)
# # # #             elif algorithm == "RSA":
# # # #                 self.rsa_decrypt(encrypted_text)
# # # #             else:
# # # #                 messagebox.showerror("خطا", f"شکستن رمز برای {algorithm} پشتیبانی نمی‌شود.")
# # # #         except Exception as e:
# # # #             messagebox.showerror("خطا", f"خطا در رمزگشایی: {str(e)}")

# # # #     def aes_encrypt(self):
# # # #         self.aes_key = get_random_bytes(32)  # 256-bit key
# # # #         iv = get_random_bytes(16)   # 128-bit IV
# # # #         data = self.get_input_data()
# # # #         if not data:
# # # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # # #             return
# # # #         cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
# # # #         ciphertext = cipher.encrypt(data.encode())
# # # #         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
# # # #         self.show_output(encrypted_base64)

# # # #     def three_des_encrypt(self):
# # # #         self.des_key = get_random_bytes(24)  # 192-bit key for 3DES
# # # #         iv = get_random_bytes(8)     # 64-bit IV
# # # #         data = self.get_input_data()
# # # #         if not data:
# # # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # # #             return
# # # #         cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)
# # # #         ciphertext = cipher.encrypt(data.encode())
# # # #         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
# # # #         self.show_output(encrypted_base64)

# # # #     def rsa_encrypt(self):
# # # #         data = self.get_input_data()
# # # #         if not data:
# # # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # # #             return
# # # #         cipher = PKCS1_OAEP.new(self.public_key)
# # # #         ciphertext = cipher.encrypt(data.encode())
# # # #         encrypted_base64 = base64.b64encode(ciphertext).decode()
# # # #         self.show_output(encrypted_base64)

# # # #     def aes_decrypt(self, encrypted_text):
# # # #         try:
# # # #             iv_and_ciphertext = base64.b64decode(encrypted_text)
# # # #             iv = iv_and_ciphertext[:16]
# # # #             ciphertext = iv_and_ciphertext[16:]
# # # #             cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)  # Use the stored AES key
# # # #             decrypted = cipher.decrypt(ciphertext)
# # # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
# # # #         except Exception as e:
# # # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # # #     def three_des_decrypt(self, encrypted_text):
# # # #         try:
# # # #             iv_and_ciphertext = base64.b64decode(encrypted_text)
# # # #             iv = iv_and_ciphertext[:8]
# # # #             ciphertext = iv_and_ciphertext[8:]
# # # #             cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)  # Use the stored 3DES key
# # # #             decrypted = cipher.decrypt(ciphertext)
# # # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
# # # #         except Exception as e:
# # # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # # #     def rsa_decrypt(self, encrypted_text):
# # # #         try:
# # # #             ciphertext = base64.b64decode(encrypted_text)
# # # #             cipher = PKCS1_OAEP.new(self.private_key)
# # # #             decrypted = cipher.decrypt(ciphertext)
# # # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
# # # #         except Exception as e:
# # # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # # #     def generate_rsa_keys(self):
# # # #         private_key = RSA.generate(2048)
# # # #         public_key = private_key.publickey()
# # # #         return private_key, public_key

# # # #     def get_input_data(self):
# # # #         if self.file_path.get():
# # # #             try:
# # # #                 with open(self.file_path.get(), "r") as file:
# # # #                     return file.read()
# # # #             except Exception as e:
# # # #                 messagebox.showerror("خطا", f"خطا در خواندن فایل: {e}")
# # # #                 return None
# # # #         else:
# # # #             return self.text_area.get("1.0", tk.END).strip()

# # # #     def show_output(self, output):
# # # #         self.output_text.config(state="normal")
# # # #         self.output_text.delete("1.0", tk.END)
# # # #         self.output_text.insert("1.0", output)
# # # #         self.output_text.config(state="disabled")

# # # #     def show_break_output(self, output):
# # # #         self.break_output_text.config(state="normal")
# # # #         self.break_output_text.delete("1.0", tk.END)
# # # #         self.break_output_text.insert("1.0", output)
# # # #         self.break_output_text.config(state="disabled")

# # # #     def copy_output(self):
# # # #         self.root.clipboard_clear()
# # # #         self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
# # # #         self.root.update()
# # # #         messagebox.showinfo("کپی شد", "خروجی کپی شد!")

# # # # if __name__ == "__main__":
# # # #     root = tk.Tk()
# # # #     app = CryptographyApp(root)
# # # #     root.mainloop()











































# # # import tkinter as tk
# # # from tkinter import filedialog, messagebox, ttk
# # # from Crypto.Cipher import AES, DES3, PKCS1_OAEP
# # # from Crypto.PublicKey import RSA
# # # from Crypto.Hash import SHA256, SHA3_256
# # # from Crypto.Random import get_random_bytes
# # # import base64
# # # import itertools
# # # import string
# # # from collections import defaultdict
# # # import threading

# # # class CTMT:
# # #     def __init__(self):
# # #         self.precomputed_table = {}
# # #         self.characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

# # #     def precompute_hashes(self, max_length=5):
# # #         for length in range(1, max_length + 1):
# # #             for attempt in itertools.product(self.characters, repeat=length):
# # #                 password = ''.join(attempt)
# # #                 sha256_hash = SHA256.new(password.encode()).hexdigest()
# # #                 self.precomputed_table[sha256_hash] = password

# # #     def crack_hash(self, hashed_value):
# # #         return self.precomputed_table.get(hashed_value, "کلمه اصلی پیدا نشد.")

# # # class CryptographyApp:
# # #     def __init__(self, root):
# # #         self.root = root
# # #         self.root.title("ابزار رمزنگاری و شکستن رمز")

# # #         # Main container
# # #         self.container = tk.Frame(root, padx=10, pady=10)
# # #         self.container.pack(fill="both", expand=True)

# # #         # Create the main tab control
# # #         self.tab_control = ttk.Notebook(self.container)

# # #         # Create primary tabs
# # #         self.encryption_tab = ttk.Frame(self.tab_control)
# # #         self.breaking_tab = ttk.Frame(self.tab_control)

# # #         self.tab_control.add(self.encryption_tab, text="رمزنگاری و رمزگشایی")
# # #         self.tab_control.add(self.breaking_tab, text="شکستن رمز")

# # #         self.tab_control.pack(expand=1, fill="both")

# # #         # Setup encryption tab
# # #         self.setup_encryption_tab()

# # #         # Setup breaking tab
# # #         self.setup_breaking_tab()

# # #         # Generate RSA keys (for asymmetric encryption)
# # #         self.private_key, self.public_key = self.generate_rsa_keys()

# # #         # Variables to store hashed value and keys
# # #         self.hashed_value = None
# # #         self.aes_key = None
# # #         self.des_key = None
# # #         self.dictionary = []
# # #         self.rainbow_table = defaultdict(list)
# # #         self.ctmt = CTMT()

# # #     def setup_encryption_tab(self):
# # #         self.algorithm_frame = ttk.LabelFrame(self.encryption_tab, text="انتخاب الگوریتم", padding=(10, 10))
# # #         self.algorithm_frame.pack(fill="x", pady=5)

# # #         tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.crypto_type = tk.StringVar(value="متقارن")
# # #         self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
# # #         self.symmetric_radio.grid(row=0, column=1, sticky="w")
# # #         self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
# # #         self.asymmetric_radio.grid(row=0, column=2, sticky="w")

# # #         tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # #         self.algorithm = ttk.Combobox(
# # #             self.algorithm_frame, values=["AES", "3DES", "RSA", "SHA-256", "SHA-3"], state="readonly"
# # #         )
# # #         self.algorithm.grid(row=1, column=1, sticky="w")
# # #         self.algorithm.current(0)

# # #         self.input_frame = ttk.LabelFrame(self.encryption_tab, text="ورودی فایل/داده", padding=(10, 10))
# # #         self.input_frame.pack(fill="x", pady=5)

# # #         tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.file_path = tk.StringVar()
# # #         self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
# # #         self.file_entry.grid(row=0, column=1, sticky="w")
# # #         self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
# # #         self.browse_button.grid(row=0, column=2, sticky="w")

# # #         tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
# # #         self.text_area = tk.Text(self.input_frame, height=5, width=50)
# # #         self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

# # #         self.output_frame = ttk.LabelFrame(self.encryption_tab, text="خروجی", padding=(10, 10))
# # #         self.output_frame.pack(fill="x", pady=5)

# # #         tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.output_text = tk.Text(self.output_frame, height=5, width=50)
# # #         self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # #         self.output_text.config(state="disabled")  # Make it read-only

# # #         self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
# # #         self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

# # #         self.action_frame = tk.Frame(self.encryption_tab, padx=10, pady=10)
# # #         self.action_frame.pack(fill="x", pady=5)

# # #         self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
# # #         self.encrypt_button.pack(side="left", padx=5)

# # #         self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
# # #         self.hash_button.pack(side="left", padx=5)

# # #     def setup_breaking_tab(self):
# # #         # Create a sub-tab control for breaking attacks
# # #         self.breaking_tab_control = ttk.Notebook(self.breaking_tab)

# # #         # Create sub-tabs for different breaking methods
# # #         self.hash_breaking_tab = ttk.Frame(self.breaking_tab_control)
# # #         self.ctmt_tab = ttk.Frame(self.breaking_tab_control)
# # #         self.rainbow_tab = ttk.Frame(self.breaking_tab_control)
# # #         self.cca_tab = ttk.Frame(self.breaking_tab_control)

# # #         self.breaking_tab_control.add(self.hash_breaking_tab, text="شکستن هش")
# # #         self.breaking_tab_control.add(self.ctmt_tab, text="CTMT")
# # #         self.breaking_tab_control.add(self.rainbow_tab, text="Rainbow Tables")
# # #         self.breaking_tab_control.add(self.cca_tab, text="Chosen Ciphertext Attack")
# # #         self.breaking_tab_control.pack(expand=1, fill="both")

# # #         # Setup each sub-tab
# # #         self.setup_hash_breaking_tab()
# # #         self.setup_ctmt_tab()
# # #         self.setup_rainbow_tab()
# # #         self.setup_cca_tab()

# # #     def setup_hash_breaking_tab(self):
# # #         tk.Label(self.hash_breaking_tab, text="متن هش شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.hash_input = tk.Entry(self.hash_breaking_tab, width=40)
# # #         self.hash_input.grid(row=0, column=1, sticky="w")

# # #         tk.Label(self.hash_breaking_tab, text="متن برای مقایسه:").grid(row=1, column=0, sticky="w", pady=5)
# # #         self.compare_input = tk.Entry(self.hash_breaking_tab, width=40)
# # #         self.compare_input.grid(row=1, column=1, sticky="w")

# # #         self.check_hash_button = tk.Button(self.hash_breaking_tab, text="بررسی هش", command=self.check_hash)
# # #         self.check_hash_button.grid(row=2, column=1, pady=5, sticky="e")

# # #         self.crack_hash_button = tk.Button(self.hash_breaking_tab, text="شکستن هش با دیکشنری", command=self.crack_hash_with_dictionary)
# # #         self.crack_hash_button.grid(row=3, column=1, pady=5, sticky="e")

# # #         self.brute_force_button = tk.Button(self.hash_breaking_tab, text="حمله Brute Force", command=self.run_brute_force_attack)
# # #         self.brute_force_button.grid(row=4, column=1, pady=5, sticky="e")

# # #         self.load_dictionary_button = tk.Button(self.hash_breaking_tab, text="بارگذاری دیکشنری", command=self.load_dictionary)
# # #         self.load_dictionary_button.grid(row=5, column=1, pady=5, sticky="e")

# # #         self.hash_output_frame = ttk.LabelFrame(self.hash_breaking_tab, text="نتیجه", padding=(10, 10))
# # #         self.hash_output_frame.grid(row=6, column=0, columnspan=2, fill="x", pady=5)

# # #         tk.Label(self.hash_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.hash_output_text = tk.Text(self.hash_output_frame, height=5, width=50)
# # #         self.hash_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # #         self.hash_output_text.config(state="disabled")

# # #     def setup_ctmt_tab(self):
# # #         tk.Label(self.ctmt_tab, text="پیش‌محاسبه هش‌ها").grid(row=0, column=0, pady=5)

# # #         self.precompute_button = tk.Button(self.ctmt_tab, text="پیش‌محاسبه هش‌ها", command=self.precompute_hashes)
# # #         self.precompute_button.grid(row=1, column=0, pady=5)

# # #         tk.Label(self.ctmt_tab, text="متن هش شده را وارد کنید:").grid(row=2, column=0, sticky="w", pady=5)
# # #         self.ctmt_hash_input = tk.Entry(self.ctmt_tab, width=40)
# # #         self.ctmt_hash_input.grid(row=2, column=1, sticky="w")

# # #         self.crack_ctmt_button = tk.Button(self.ctmt_tab, text="شکستن هش با CTMT", command=self.crack_hash_with_ctmt)
# # #         self.crack_ctmt_button.grid(row=3, column=1, pady=5, sticky="e")

# # #         self.ctmt_output_frame = ttk.LabelFrame(self.ctmt_tab, text="نتیجه", padding=(10, 10))
# # #         self.ctmt_output_frame.grid(row=4, column=0, columnspan=2, fill="x", pady=5)

# # #         tk.Label(self.ctmt_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.ctmt_output_text = tk.Text(self.ctmt_output_frame, height=5, width=50)
# # #         self.ctmt_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # #         self.ctmt_output_text.config(state="disabled")

# # #     def setup_rainbow_tab(self):
# # #         tk.Label(self.rainbow_tab, text="متن هش را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.rainbow_hash_input = tk.Entry(self.rainbow_tab, width=40)
# # #         self.rainbow_hash_input.grid(row=0, column=1, sticky="w")

# # #         self.rainbow_crack_button = tk.Button(self.rainbow_tab, text="شکستن هش با Rainbow Tables", command=self.crack_with_rainbow_tables)
# # #         self.rainbow_crack_button.grid(row=1, column=1, pady=5, sticky="e")

# # #         self.rainbow_output_frame = ttk.LabelFrame(self.rainbow_tab, text="نتیجه", padding=(10, 10))
# # #         self.rainbow_output_frame.grid(row=2, column=0, columnspan=2, fill="x", pady=5)

# # #         tk.Label(self.rainbow_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.rainbow_output_text = tk.Text(self.rainbow_output_frame, height=5, width=50)
# # #         self.rainbow_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # #         self.rainbow_output_text.config(state="disabled")

# # #     def setup_cca_tab(self):
# # #         tk.Label(self.cca_tab, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.cca_input = tk.Entry(self.cca_tab, width=40)
# # #         self.cca_input.grid(row=0, column=1, sticky="w")

# # #         self.cca_attack_button = tk.Button(self.cca_tab, text="اجرای حمله CCA", command=self.run_cca_attack)
# # #         self.cca_attack_button.grid(row=1, column=1, pady=5, sticky="e")

# # #         self.cca_output_frame = ttk.LabelFrame(self.cca_tab, text="نتیجه", padding=(10, 10))
# # #         self.cca_output_frame.grid(row=2, column=0, columnspan=2, fill="x", pady=5)

# # #         tk.Label(self.cca_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# # #         self.cca_output_text = tk.Text(self.cca_output_frame, height=5, width=50)
# # #         self.cca_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# # #         self.cca_output_text.config(state="disabled")

# # #     def run_cca_attack(self):
# # #         self.cca_output_text.config(state="normal")
# # #         self.cca_output_text.delete("1.0", tk.END)
# # #         self.cca_output_text.insert("1.0", "حمله CCA با موفقیت انجام شد.")
# # #         self.cca_output_text.config(state="disabled")

# # #     def browse_file(self):
# # #         file_path = filedialog.askopenfilename()
# # #         if file_path:
# # #             self.file_path.set(file_path)

# # #     def load_dictionary(self):
# # #         file_path = filedialog.askopenfilename()
# # #         if file_path:
# # #             try:
# # #                 with open(file_path, 'r') as file:
# # #                     self.dictionary = [line.strip() for line in file.readlines()]
# # #                 messagebox.showinfo("موفقیت", "دیکشنری با موفقیت بارگذاری شد.")
# # #             except Exception as e:
# # #                 messagebox.showerror("خطا", f"خطا در بارگذاری دیکشنری: {e}")

# # #     def encrypt_data(self):
# # #         algorithm = self.algorithm.get()
# # #         if algorithm == "AES":
# # #             self.aes_encrypt()
# # #         elif algorithm == "3DES":
# # #             self.three_des_encrypt()
# # #         elif algorithm == "RSA":
# # #             self.rsa_encrypt()
# # #         else:
# # #             messagebox.showerror("خطا", f"رمزگذاری برای {algorithm} پشتیبانی نمی‌شود.")

# # #     def generate_hash(self):
# # #         algorithm = self.algorithm.get()
# # #         data = self.get_input_data()
# # #         if not data:
# # #             messagebox.showerror("خطا", "لطفاً متنی برای هش کردن وارد کنید.")
# # #             return
# # #         if algorithm == "SHA-256":
# # #             digest = SHA256.new()
# # #         elif algorithm == "SHA-3":
# # #             digest = SHA3_256.new()
# # #         else:
# # #             messagebox.showerror("خطا", f"هشینگ برای {algorithm} پشتیبانی نمی‌شود.")
# # #             return
        
# # #         digest.update(data.encode())
# # #         self.hashed_value = digest.hexdigest()
# # #         self.show_output(self.hashed_value)
# # #         self.populate_rainbow_table(data)

# # #     def populate_rainbow_table(self, original_data):
# # #         sha256_hash = SHA256.new(original_data.encode()).hexdigest()
# # #         self.rainbow_table[sha256_hash].append(original_data)

# # #     def check_hash(self):
# # #         hashed_value = self.hash_input.get().strip()
# # #         comparison_input = self.compare_input.get().strip()

# # #         if not hashed_value or not comparison_input:
# # #             messagebox.showerror("خطا", "لطفاً هر دو متن را وارد کنید.")
# # #             return

# # #         sha256_hash = SHA256.new(comparison_input.encode()).hexdigest()

# # #         if sha256_hash == hashed_value:
# # #             self.show_hash_break_output("متن صحیح است!")
# # #         else:
# # #             self.show_hash_break_output("متن صحیح نیست!")

# # #     def crack_hash_with_dictionary(self):
# # #         hashed_value = self.hash_input.get().strip()
# # #         if not hashed_value:
# # #             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
# # #             return
        
# # #         if not self.dictionary:
# # #             messagebox.showerror("خطا", "لطفاً ابتدا دیکشنری را بارگذاری کنید.")
# # #             return

# # #         found = False
# # #         for word in self.dictionary:
# # #             sha256_hash = SHA256.new(word.encode()).hexdigest()
# # #             if sha256_hash == hashed_value:
# # #                 self.show_hash_break_output(f"کلمه اصلی: {word}")
# # #                 found = True
# # #                 break
        
# # #         if not found:
# # #             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

# # #     def run_brute_force_attack(self):
# # #         hashed_value = self.hash_input.get().strip()
# # #         if not hashed_value:
# # #             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
# # #             return

# # #         threading.Thread(target=self.brute_force_attack, args=(hashed_value,)).start()

# # #     def brute_force_attack(self, hashed_value):
# # #         characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
# # #         found = False
# # #         for length in range(1, 6):
# # #             for attempt in itertools.product(characters, repeat=length):
# # #                 password = ''.join(attempt)
# # #                 sha256_hash = SHA256.new(password.encode()).hexdigest()
# # #                 if sha256_hash == hashed_value:
# # #                     self.show_hash_break_output(f"کلمه اصلی: {password}")
# # #                     found = True
# # #                     break
# # #             if found:
# # #                 break
# # #         if not found:
# # #             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

# # #     def precompute_hashes(self):
# # #         self.ctmt.precompute_hashes(5)
# # #         messagebox.showinfo("موفقیت", "هش‌ها با موفقیت پیش‌محاسبه شدند!")

# # #     def crack_hash_with_ctmt(self):
# # #         hashed_value = self.ctmt_hash_input.get().strip()
# # #         if not hashed_value:
# # #             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
# # #             return

# # #         result = self.ctmt.crack_hash(hashed_value)
# # #         self.show_hash_break_output(result)

# # #     def show_hash_break_output(self, output):
# # #         self.hash_output_text.config(state="normal")
# # #         self.hash_output_text.delete("1.0", tk.END)
# # #         self.hash_output_text.insert("1.0", output)
# # #         self.hash_output_text.config(state="disabled")

# # #     def break_data(self):
# # #         algorithm = self.break_algorithm.get()
# # #         encrypted_text = self.break_input_text.get("1.0", tk.END).strip()
# # #         try:
# # #             if algorithm == "AES":
# # #                 self.aes_decrypt(encrypted_text)
# # #             elif algorithm == "3DES":
# # #                 self.three_des_decrypt(encrypted_text)
# # #             elif algorithm == "RSA":
# # #                 self.rsa_decrypt(encrypted_text)
# # #             else:
# # #                 messagebox.showerror("خطا", f"شکستن رمز برای {algorithm} پشتیبانی نمی‌شود.")
# # #         except Exception as e:
# # #             messagebox.showerror("خطا", f"خطا در رمزگشایی: {str(e)}")

# # #     def aes_encrypt(self):
# # #         self.aes_key = get_random_bytes(32)
# # #         iv = get_random_bytes(16)
# # #         data = self.get_input_data()
# # #         if not data:
# # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # #             return
# # #         cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
# # #         ciphertext = cipher.encrypt(data.encode())
# # #         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
# # #         self.show_output(encrypted_base64)

# # #     def three_des_encrypt(self):
# # #         self.des_key = get_random_bytes(24)
# # #         iv = get_random_bytes(8)
# # #         data = self.get_input_data()
# # #         if not data:
# # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # #             return
# # #         cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)
# # #         ciphertext = cipher.encrypt(data.encode())
# # #         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
# # #         self.show_output(encrypted_base64)

# # #     def rsa_encrypt(self):
# # #         data = self.get_input_data()
# # #         if not data:
# # #             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
# # #             return
# # #         cipher = PKCS1_OAEP.new(self.public_key)
# # #         ciphertext = cipher.encrypt(data.encode())
# # #         encrypted_base64 = base64.b64encode(ciphertext).decode()
# # #         self.show_output(encrypted_base64)

# # #     def aes_decrypt(self, encrypted_text):
# # #         try:
# # #             iv_and_ciphertext = base64.b64decode(encrypted_text)
# # #             iv = iv_and_ciphertext[:16]
# # #             ciphertext = iv_and_ciphertext[16:]
# # #             cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
# # #             decrypted = cipher.decrypt(ciphertext)
# # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))
# # #         except Exception as e:
# # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # #     def three_des_decrypt(self, encrypted_text):
# # #         try:
# # #             iv_and_ciphertext = base64.b64decode(encrypted_text)
# # #             iv = iv_and_ciphertext[:8]
# # #             ciphertext = iv_and_ciphertext[8:]
# # #             cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)
# # #             decrypted = cipher.decrypt(ciphertext)
# # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))
# # #         except Exception as e:
# # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # #     def rsa_decrypt(self, encrypted_text):
# # #         try:
# # #             ciphertext = base64.b64decode(encrypted_text)
# # #             cipher = PKCS1_OAEP.new(self.private_key)
# # #             decrypted = cipher.decrypt(ciphertext)
# # #             self.show_break_output(decrypted.decode('utf-8', 'ignore'))
# # #         except Exception as e:
# # #             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

# # #     def generate_rsa_keys(self):
# # #         private_key = RSA.generate(2048)
# # #         public_key = private_key.publickey()
# # #         return private_key, public_key

# # #     def get_input_data(self):
# # #         if self.file_path.get():
# # #             try:
# # #                 with open(self.file_path.get(), "r") as file:
# # #                     return file.read()
# # #             except Exception as e:
# # #                 messagebox.showerror("خطا", f"خطا در خواندن فایل: {e}")
# # #                 return None
# # #         else:
# # #             return self.text_area.get("1.0", tk.END).strip()

# # #     def show_output(self, output):
# # #         self.output_text.config(state="normal")
# # #         self.output_text.delete("1.0", tk.END)
# # #         self.output_text.insert("1.0", output)
# # #         self.output_text.config(state="disabled")

# # #     def show_break_output(self, output):
# # #         self.hash_output_text.config(state="normal")
# # #         self.hash_output_text.delete("1.0", tk.END)
# # #         self.hash_output_text.insert("1.0", output)
# # #         self.hash_output_text.config(state="disabled")

# # #     def copy_output(self):
# # #         self.root.clipboard_clear()
# # #         self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
# # #         self.root.update()
# # #         messagebox.showinfo("کپی شد", "خروجی کپی شد!")

# # # if __name__ == "__main__":
# # #     root = tk.Tk()
# # #     app = CryptographyApp(root)
# # #     root.mainloop()













































































# # import tkinter as tk
# # from tkinter import filedialog, messagebox, ttk
# # from Crypto.Cipher import AES, DES3, PKCS1_OAEP
# # from Crypto.PublicKey import RSA
# # from Crypto.Hash import SHA256, SHA3_256
# # from Crypto.Random import get_random_bytes
# # import base64
# # import itertools
# # import string
# # from collections import defaultdict
# # import threading

# # class CTMT:
# #     def __init__(self):
# #         self.precomputed_table = {}
# #         self.characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

# #     def precompute_hashes(self, max_length=5):
# #         for length in range(1, max_length + 1):
# #             for attempt in itertools.product(self.characters, repeat=length):
# #                 password = ''.join(attempt)
# #                 sha256_hash = SHA256.new(password.encode()).hexdigest()
# #                 self.precomputed_table[sha256_hash] = password

# #     def crack_hash(self, hashed_value):
# #         return self.precomputed_table.get(hashed_value, "کلمه اصلی پیدا نشد.")

# # class CryptographyApp:
# #     def __init__(self, root):
# #         self.root = root
# #         self.root.title("ابزار رمزنگاری و شکستن رمز")

# #         # Main container
# #         self.container = tk.Frame(root, padx=10, pady=10)
# #         self.container.pack(fill="both", expand=True)

# #         # Create the tab control
# #         self.tab_control = ttk.Notebook(self.container)

# #         # Create tabs
# #         self.encryption_tab = ttk.Frame(self.tab_control)
# #         self.breaking_tab = ttk.Frame(self.tab_control)

# #         self.tab_control.add(self.encryption_tab, text="رمزنگاری و رمزگشایی")
# #         self.tab_control.add(self.breaking_tab, text="شکستن رمز")

# #         self.tab_control.pack(expand=1, fill="both")

# #         # Setup encryption tab
# #         self.setup_encryption_tab()

# #         # Setup breaking tab
# #         self.setup_breaking_tab()

# #         # Generate RSA keys (for asymmetric encryption)
# #         self.private_key, self.public_key = self.generate_rsa_keys()

# #         # Variables to store hashed value and keys
# #         self.hashed_value = None
# #         self.aes_key = None
# #         self.des_key = None
# #         self.dictionary = []  # For storing dictionary words
# #         self.rainbow_table = defaultdict(list)  # For storing rainbow table entries
# #         self.ctmt = CTMT()  # Create CTMT instance here

# #     def setup_encryption_tab(self):
# #         # Section: Algorithm Selection
# #         self.algorithm_frame = ttk.LabelFrame(self.encryption_tab, text="انتخاب الگوریتم", padding=(10, 10))
# #         self.algorithm_frame.pack(fill="x", pady=5)

# #         tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
# #         self.crypto_type = tk.StringVar(value="متقارن")
# #         self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
# #         self.symmetric_radio.grid(row=0, column=1, sticky="w")
# #         self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
# #         self.asymmetric_radio.grid(row=0, column=2, sticky="w")

# #         tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
# #         self.algorithm = ttk.Combobox(
# #             self.algorithm_frame, values=["AES", "3DES", "RSA", "SHA-256", "SHA-3"], state="readonly"
# #         )
# #         self.algorithm.grid(row=1, column=1, sticky="w")
# #         self.algorithm.current(0)

# #         # Section: File/Data Input
# #         self.input_frame = ttk.LabelFrame(self.encryption_tab, text="ورودی فایل/داده", padding=(10, 10))
# #         self.input_frame.pack(fill="x", pady=5)

# #         tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
# #         self.file_path = tk.StringVar()
# #         self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
# #         self.file_entry.grid(row=0, column=1, sticky="w")
# #         self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
# #         self.browse_button.grid(row=0, column=2, sticky="w")

# #         tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
# #         self.text_area = tk.Text(self.input_frame, height=5, width=50)
# #         self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

# #         # Section: Output Box
# #         self.output_frame = ttk.LabelFrame(self.encryption_tab, text="خروجی", padding=(10, 10))
# #         self.output_frame.pack(fill="x", pady=5)

# #         tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
# #         self.output_text = tk.Text(self.output_frame, height=5, width=50)
# #         self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
# #         self.output_text.config(state="disabled")  # Make it read-only

# #         self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
# #         self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

# #         # Section: Action Buttons
# #         self.action_frame = tk.Frame(self.encryption_tab, padx=10, pady=10)
# #         self.action_frame.pack(fill="x", pady=5)

# #         self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
# #         self.encrypt_button.pack(side="left", padx=5)

# #         self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
# #         self.hash_button.pack(side="left", padx=5)

# #     def setup_breaking_tab(self):
# #         # Create a frame for the breaking tools
# #         self.breaking_tools_frame = ttk.LabelFrame(self.breaking_tab, text="ابزارهای رمز شکنی", padding=(10, 10))
# #         self.breaking_tools_frame.pack(fill="both", expand=True, padx=10, pady=10)

# #         # Section: Attack Types
# #         self.attack_types_frame = ttk.Frame(self.breaking_tools_frame)
# #         self.attack_types_frame.pack(fill="x")

# #         tk.Button(self.attack_types_frame, text="شکستن هش", command=self.show_hash_breaking).pack(side="left", padx=5, pady=5)
# #         tk.Button(self.attack_types_frame, text="حمله Brute Force", command=self.show_brute_force).pack(side="left", padx=5, pady=5)
# #         tk.Button(self.attack_types_frame, text="حمله دیکشنری", command=self.show_dictionary_attack).pack(side="left", padx=5, pady=5)
# #         tk.Button(self.attack_types_frame, text="Rainbow Tables", command=self.show_rainbow_tables).pack(side="left", padx=5, pady=5)
# #         tk.Button(self.attack_types_frame, text="CTMT", command=self.show_ctmt).pack(side="left", padx=5, pady=5)
# #         tk.Button(self.attack_types_frame, text="Chosen Ciphertext Attack", command=self.show_cca).pack(side="left", padx=5, pady=5)

# #         # Main content area for breaking attacks
# #         self.content_frame = tk.Frame(self.breaking_tools_frame)
# #         self.content_frame.pack(fill="both", expand=True)

# #         # Show the default breaking attack
# #         self.show_hash_breaking()

# #     def show_hash_breaking(self):
# #         self.clear_content_frame()
# #         HashBreakingFrame(self.content_frame).pack(fill="both", expand=True)

# #     def show_brute_force(self):
# #         self.clear_content_frame()
# #         BruteForceFrame(self.content_frame).pack(fill="both", expand=True)

# #     def show_dictionary_attack(self):
# #         self.clear_content_frame()
# #         DictionaryAttackFrame(self.content_frame).pack(fill="both", expand=True)

# #     def show_rainbow_tables(self):
# #         self.clear_content_frame()
# #         RainbowTableFrame(self.content_frame).pack(fill="both", expand=True)

# #     def show_ctmt(self):
# #         self.clear_content_frame()
# #         CTMTFrame(self.content_frame).pack(fill="both", expand=True)

# #     def show_cca(self):
# #         self.clear_content_frame()
# #         CCAFrame(self.content_frame).pack(fill="both", expand=True)

# #     def clear_content_frame(self):
# #         for widget in self.content_frame.winfo_children():
# #             widget.destroy()

# #     def browse_file(self):
# #         file_path = filedialog.askopenfilename()
# #         if file_path:
# #             self.file_path.set(file_path)

# #     def encrypt_data(self):
# #         # Your encryption logic here
# #         pass

# #     def generate_hash(self):
# #         # Your hash generation logic here
# #         pass

# #     def copy_output(self):
# #         self.root.clipboard_clear()
# #         self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
# #         self.root.update()
# #         messagebox.showinfo("کپی شد", "خروجی کپی شد!")

# #     def generate_rsa_keys(self):
# #         private_key = RSA.generate(2048)
# #         public_key = private_key.publickey()
# #         return private_key, public_key

# # class HashBreakingFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="شکستن هش", font=("Arial", 20)).pack(pady=10)
# #         tk.Label(self, text="متن هش شده را وارد کنید:").pack(pady=5)
# #         self.hash_input = tk.Entry(self)
# #         self.hash_input.pack(pady=5)
# #         tk.Button(self, text="بررسی هش", command=self.check_hash).pack(pady=10)

# #     def check_hash(self):
# #         # Implement your hash checking logic
# #         pass

# # class BruteForceFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="حمله Brute Force", font=("Arial", 20)).pack(pady=10)
# #         # Add your widgets for brute force attack here

# # class DictionaryAttackFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="حمله دیکشنری", font=("Arial", 20)).pack(pady=10)
# #         # Add your widgets for dictionary attack here

# # class RainbowTableFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="Rainbow Tables", font=("Arial", 20)).pack(pady=10)
# #         # Add your widgets for rainbow tables here

# # class CTMTFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="CTMT", font=("Arial", 20)).pack(pady=10)
# #         # Add your widgets for CTMT here

# # class CCAFrame(tk.Frame):
# #     def __init__(self, parent):
# #         super().__init__(parent)
# #         tk.Label(self, text="Chosen Ciphertext Attack", font=("Arial", 20)).pack(pady=10)
# #         # Add your widgets for CCA here

# # if __name__ == "__main__":
# #     root = tk.Tk()
# #     app = CryptographyApp(root)
# #     root.mainloop()

























































# import tkinter as tk
# from tkinter import filedialog, messagebox, ttk
# from Crypto.Cipher import AES, DES3, PKCS1_OAEP
# from Crypto.PublicKey import RSA
# from Crypto.Hash import SHA256, SHA3_256
# from Crypto.Random import get_random_bytes
# import base64
# import itertools
# import string
# from collections import defaultdict
# import threading
# import time
# import itertools
# import threading
# from concurrent.futures import ThreadPoolExecutor
# import matplotlib.pyplot as plt
# import numpy as np
# from scipy import stats

# class CTMT:
#     def __init__(self):
#         self.precomputed_table = {}
#         self.characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

#     def precompute_hashes(self, max_length=5):
#         for length in range(1, max_length + 1):
#             for attempt in itertools.product(self.characters, repeat=length):
#                 password = ''.join(attempt)
#                 sha256_hash = SHA256.new(password.encode()).hexdigest()
#                 self.precomputed_table[sha256_hash] = password

#     def crack_hash(self, hashed_value):
#         return self.precomputed_table.get(hashed_value, "کلمه اصلی پیدا نشد.")

# class CryptographyApp:
#     def setup_cryptanalysis_tab(self):
#     # ایجاد زبانه جدید برای حملات رمزشکنی
#         self.cryptanalysis_tab = ttk.Frame(self.tab_control)
#         self.tab_control.add(self.cryptanalysis_tab, text="تحلیل رمزنگاری")

#     # بخش حملات مختلف
#     sections = [
#         "Brute Force Attack",
#         "Dictionary Attack", 
#         "Rainbow Table Attack",
#         "Timing Attacks",
#         "Side-Channel Attacks",
#         "Key Recovery",
#         "Chosen Ciphertext Attack",
#         "Statistical Cryptanalysis"
#     ]

#     # ایجاد فریم برای هر نوع حمله
#     for i, section in enumerate(sections):
#         frame = ttk.LabelFrame(self.cryptanalysis_tab, text=section, padding=(10, 10))
#         frame.pack(fill="x", pady=5)

#         # دکمه نمایش اطلاعات تئوریک
#         info_button = tk.Button(frame, text="اطلاعات", 
#                                 command=lambda s=section: self.show_attack_info(s))
#         info_button.pack(side="left", padx=5)

#         # دکمه اجرای حمله
#         attack_button = tk.Button(frame, text="اجرای حمله", 
#                                   command=lambda s=section: self.run_cryptanalysis_attack(s))
#         attack_button.pack(side="left", padx=5)

#         self.cryptanalysis_output = tk.Text(self.cryptanalysis_tab, height=10, width=50)
#         self.cryptanalysis_output.pack(pady=10)
    
#     def __init__(self, root):
#         self.root = root
#         self.root.title("ابزار رمزنگاری و شکستن رمز")

#         # Main container
#         self.container = tk.Frame(root, padx=10, pady=10)
#         self.container.pack(fill="both", expand=True)

#         # Create the tab control
#         self.tab_control = ttk.Notebook(self.container)

#         # Create tabs
#         self.encryption_tab = ttk.Frame(self.tab_control)
#         self.breaking_tab = ttk.Frame(self.tab_control)

#         self.tab_control.add(self.encryption_tab, text="رمزنگاری و رمزگشایی")
#         self.tab_control.add(self.breaking_tab, text="شکستن رمز")

#         self.tab_control.pack(expand=1, fill="both")

#         # Setup encryption tab
#         self.setup_encryption_tab()

#         # Setup breaking tab
#         self.setup_breaking_tab()

#         # Generate RSA keys (for asymmetric encryption)
#         self.private_key, self.public_key = self.generate_rsa_keys()

#         # Variable to store hashed value and keys
#         self.hashed_value = None
#         self.aes_key = None
#         self.des_key = None
#         self.dictionary = []  # For storing dictionary words
#         self.rainbow_table = defaultdict(list)  # For storing rainbow table entries
#         self.ctmt = CTMT()  # Create CTMT instance here

#     def setup_encryption_tab(self):
#         # Section: Algorithm Selection
#         self.algorithm_frame = ttk.LabelFrame(self.encryption_tab, text="انتخاب الگوریتم", padding=(10, 10))
#         self.algorithm_frame.pack(fill="x", pady=5)

#         tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
#         self.crypto_type = tk.StringVar(value="متقارن")
#         self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
#         self.symmetric_radio.grid(row=0, column=1, sticky="w")
#         self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
#         self.asymmetric_radio.grid(row=0, column=2, sticky="w")

#         tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
#         self.algorithm = ttk.Combobox(
#             self.algorithm_frame, values=[
#                 "AES", "3DES", "RSA", "SHA-256", "SHA-3"
#             ], state="readonly"
#         )
#         self.algorithm.grid(row=1, column=1, sticky="w")
#         self.algorithm.current(0)

#         # Section: File/Data Input
#         self.input_frame = ttk.LabelFrame(self.encryption_tab, text="ورودی فایل/داده", padding=(10, 10))
#         self.input_frame.pack(fill="x", pady=5)

#         tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
#         self.file_path = tk.StringVar()
#         self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
#         self.file_entry.grid(row=0, column=1, sticky="w")
#         self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
#         self.browse_button.grid(row=0, column=2, sticky="w")

#         tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
#         self.text_area = tk.Text(self.input_frame, height=5, width=50)
#         self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

#         # Section: Output Box
#         self.output_frame = ttk.LabelFrame(self.encryption_tab, text="خروجی", padding=(10, 10))
#         self.output_frame.pack(fill="x", pady=5)

#         tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
#         self.output_text = tk.Text(self.output_frame, height=5, width=50)
#         self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
#         self.output_text.config(state="disabled")  # Make it read-only

#         self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
#         self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

#         # Section: Action Buttons
#         self.action_frame = tk.Frame(self.encryption_tab, padx=10, pady=10)
#         self.action_frame.pack(fill="x", pady=5)

#         self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
#         self.encrypt_button.pack(side="left", padx=5)

#         self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
#         self.hash_button.pack(side="left", padx=5)

#     def setup_breaking_tab(self):
#         # Section: Break Algorithm
#         self.break_algorithm_frame = ttk.LabelFrame(self.breaking_tab, text="شکستن رمز", padding=(10, 10))
#         self.break_algorithm_frame.pack(fill="x", pady=5)

#         tk.Label(self.break_algorithm_frame, text="متن رمز شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
#         self.break_input_text = tk.Text(self.break_algorithm_frame, height=5, width=50)
#         self.break_input_text.grid(row=0, column=1, columnspan=2, sticky="w")

#         tk.Label(self.break_algorithm_frame, text="الگوریتم را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
#         self.break_algorithm = ttk.Combobox(
#             self.break_algorithm_frame, values=["AES", "3DES", "RSA"], state="readonly"
#         )
#         self.break_algorithm.grid(row=1, column=1, sticky="w")
#         self.break_algorithm.current(0)

#         self.break_button = tk.Button(self.break_algorithm_frame, text="شکستن رمز", command=self.break_data)
#         self.break_button.grid(row=2, column=1, pady=5, sticky="e")

#         # Section: Hash Breaking
#         self.hash_frame = ttk.LabelFrame(self.breaking_tab, text="شکستن هش", padding=(10, 10))
#         self.hash_frame.pack(fill="x", pady=5)

#         tk.Label(self.hash_frame, text="متن هش شده را وارد کنید:").grid(row=0, column=0, sticky="w", pady=5)
#         self.hash_input = tk.Entry(self.hash_frame, width=40)
#         self.hash_input.grid(row=0, column=1, sticky="w")

#         tk.Label(self.hash_frame, text="متن برای مقایسه:").grid(row=1, column=0, sticky="w", pady=5)
#         self.compare_input = tk.Entry(self.hash_frame, width=40)
#         self.compare_input.grid(row=1, column=1, sticky="w")

#         self.check_hash_button = tk.Button(self.hash_frame, text="بررسی هش", command=self.check_hash)
#         self.check_hash_button.grid(row=2, column=1, pady=5, sticky="e")

#         self.crack_hash_button = tk.Button(self.hash_frame, text="شکستن هش با دیکشنری", command=self.crack_hash_with_dictionary)
#         self.crack_hash_button.grid(row=3, column=1, pady=5, sticky="e")

#         self.brute_force_button = tk.Button(self.hash_frame, text="حمله Brute Force", command=self.run_brute_force_attack)
#         self.brute_force_button.grid(row=4, column=1, pady=5, sticky="e")

#         # Section: Load Dictionary
#         self.load_dictionary_button = tk.Button(self.hash_frame, text="بارگذاری دیکشنری", command=self.load_dictionary)
#         self.load_dictionary_button.grid(row=5, column=1, pady=5, sticky="e")

#         # Section: CTMT
#         self.ctmt_frame = ttk.LabelFrame(self.breaking_tab, text="حمله CTMT", padding=(10, 10))
#         self.ctmt_frame.pack(fill="x", pady=5)

#         self.precompute_button = tk.Button(self.ctmt_frame, text="پیش‌محاسبه هش‌ها", command=self.precompute_hashes)
#         self.precompute_button.grid(row=0, column=0, pady=5)

#         tk.Label(self.ctmt_frame, text="متن هش شده را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
#         self.ctmt_hash_input = tk.Entry(self.ctmt_frame, width=40)
#         self.ctmt_hash_input.grid(row=1, column=1, sticky="w")

#         self.crack_ctmt_button = tk.Button(self.ctmt_frame, text="شکستن هش با CTMT", command=self.crack_hash_with_ctmt)
#         self.crack_ctmt_button.grid(row=2, column=1, pady=5, sticky="e")

#         # Output Frame for Hash Breaking Results
#         self.hash_output_frame = ttk.LabelFrame(self.breaking_tab, text="نتیجه", padding=(10, 10))
#         self.hash_output_frame.pack(fill="x", pady=5)

#         tk.Label(self.hash_output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
#         self.hash_output_text = tk.Text(self.hash_output_frame, height=5, width=50)
#         self.hash_output_text.grid(row=0, column=1, columnspan=2, sticky="w")
#         self.hash_output_text.config(state="disabled")

#     def browse_file(self):
#         file_path = filedialog.askopenfilename()
#         if file_path:
#             self.file_path.set(file_path)

#     def load_dictionary(self):
#         file_path = filedialog.askopenfilename()
#         if file_path:
#             try:
#                 with open(file_path, 'r') as file:
#                     self.dictionary = [line.strip() for line in file.readlines()]
#                 messagebox.showinfo("موفقیت", "دیکشنری با موفقیت بارگذاری شد.")
#             except Exception as e:
#                 messagebox.showerror("خطا", f"خطا در بارگذاری دیکشنری: {e}")

#     def encrypt_data(self):
#         algorithm = self.algorithm.get()
#         if algorithm == "AES":
#             self.aes_encrypt()
#         elif algorithm == "3DES":
#             self.three_des_encrypt()
#         elif algorithm == "RSA":
#             self.rsa_encrypt()
#         else:
#             messagebox.showerror("خطا", f"رمزگذاری برای {algorithm} پشتیبانی نمی‌شود.")

#     def generate_hash(self):
#         algorithm = self.algorithm.get()
#         data = self.get_input_data()
#         if not data:
#             messagebox.showerror("خطا", "لطفاً متنی برای هش کردن وارد کنید.")
#             return
#         if algorithm == "SHA-256":
#             digest = SHA256.new()
#         elif algorithm == "SHA-3":
#             digest = SHA3_256.new()
#         else:
#             messagebox.showerror("خطا", f"هشینگ برای {algorithm} پشتیبانی نمی‌شود.")
#             return
        
#         digest.update(data.encode())
#         self.hashed_value = digest.hexdigest()  # Store the hashed value
#         self.show_output(self.hashed_value)
#         self.populate_rainbow_table(data)  # Populate the rainbow table with the original data

#     def populate_rainbow_table(self, original_data):
#         # Add the original data and its hash to the rainbow table
#         sha256_hash = SHA256.new(original_data.encode()).hexdigest()
#         self.rainbow_table[sha256_hash].append(original_data)

#     def check_hash(self):
#         # Get the hashed value and comparison input
#         hashed_value = self.hash_input.get().strip()
#         comparison_input = self.compare_input.get().strip()

#         if not hashed_value or not comparison_input:
#             messagebox.showerror("خطا", "لطفاً هر دو متن را وارد کنید.")
#             return

#         # Check if the input matches the hash
#         sha256_hash = SHA256.new(comparison_input.encode()).hexdigest()

#         if sha256_hash == hashed_value:
#             self.show_hash_break_output("متن صحیح است!")
#         else:
#             self.show_hash_break_output("متن صحیح نیست!")

#     def crack_hash_with_dictionary(self):
#         hashed_value = self.hash_input.get().strip()
#         if not hashed_value:
#             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
#             return
        
#         if not self.dictionary:
#             messagebox.showerror("خطا", "لطفاً ابتدا دیکشنری را بارگذاری کنید.")
#             return

#         found = False
#         for word in self.dictionary:
#             sha256_hash = SHA256.new(word.encode()).hexdigest()
#             if sha256_hash == hashed_value:
#                 self.show_hash_break_output(f"کلمه اصلی: {word}")
#                 found = True
#                 break
        
#         if not found:
#             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

#     def run_brute_force_attack(self):
#         hashed_value = self.hash_input.get().strip()
#         if not hashed_value:
#             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
#             return

#         # Start the brute force attack in a separate thread
#         threading.Thread(target=self.brute_force_attack, args=(hashed_value,)).start()

#     def brute_force_attack(self, hashed_value):
#         characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
#         found = False
#         for length in range(1, 6):  # Try lengths from 1 to 5
#             for attempt in itertools.product(characters, repeat=length):
#                 password = ''.join(attempt)
#                 sha256_hash = SHA256.new(password.encode()).hexdigest()
#                 if sha256_hash == hashed_value:
#                     self.show_hash_break_output(f"کلمه اصلی: {password}")
#                     found = True
#                     break  # Exit the loop if the password is found
#             if found:
#                 break  # Exit outer loop if the password is found
#         if not found:
#             self.show_hash_break_output("کلمه اصلی پیدا نشد.")

#     def precompute_hashes(self):
#         self.ctmt.precompute_hashes(5)  # Precompute hashes for lengths up to 5
#         messagebox.showinfo("موفقیت", "هش‌ها با موفقیت پیش‌محاسبه شدند!")

#     def crack_hash_with_ctmt(self):
#         hashed_value = self.ctmt_hash_input.get().strip()
#         if not hashed_value:
#             messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
#             return

#         result = self.ctmt.crack_hash(hashed_value)
#         self.show_hash_break_output(result)

#     def show_hash_break_output(self, output):
#         self.hash_output_text.config(state="normal")
#         self.hash_output_text.delete("1.0", tk.END)
#         self.hash_output_text.insert("1.0", output)
#         self.hash_output_text.config(state="disabled")

#     def break_data(self):
#         algorithm = self.break_algorithm.get()
#         encrypted_text = self.break_input_text.get("1.0", tk.END).strip()
#         try:
#             if algorithm == "AES":
#                 self.aes_decrypt(encrypted_text)
#             elif algorithm == "3DES":
#                 self.three_des_decrypt(encrypted_text)
#             elif algorithm == "RSA":
#                 self.rsa_decrypt(encrypted_text)
#             else:
#                 messagebox.showerror("خطا", f"شکستن رمز برای {algorithm} پشتیبانی نمی‌شود.")
#         except Exception as e:
#             messagebox.showerror("خطا", f"خطا در رمزگشایی: {str(e)}")

#     def aes_encrypt(self):
#         self.aes_key = get_random_bytes(32)  # 256-bit key
#         iv = get_random_bytes(16)   # 128-bit IV
#         data = self.get_input_data()
#         if not data:
#             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
#             return
#         cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
#         ciphertext = cipher.encrypt(data.encode())
#         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
#         self.show_output(encrypted_base64)

#     def three_des_encrypt(self):
#         self.des_key = get_random_bytes(24)  # 192-bit key for 3DES
#         iv = get_random_bytes(8)     # 64-bit IV
#         data = self.get_input_data()
#         if not data:
#             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
#             return
#         cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)
#         ciphertext = cipher.encrypt(data.encode())
#         encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
#         self.show_output(encrypted_base64)

#     def rsa_encrypt(self):
#         data = self.get_input_data()
#         if not data:
#             messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
#             return
#         cipher = PKCS1_OAEP.new(self.public_key)
#         ciphertext = cipher.encrypt(data.encode())
#         encrypted_base64 = base64.b64encode(ciphertext).decode()
#         self.show_output(encrypted_base64)

#     def aes_decrypt(self, encrypted_text):
#         try:
#             iv_and_ciphertext = base64.b64decode(encrypted_text)
#             iv = iv_and_ciphertext[:16]
#             ciphertext = iv_and_ciphertext[16:]
#             cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)  # Use the stored AES key
#             decrypted = cipher.decrypt(ciphertext)
#             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
#         except Exception as e:
#             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

#     def three_des_decrypt(self, encrypted_text):
#         try:
#             iv_and_ciphertext = base64.b64decode(encrypted_text)
#             iv = iv_and_ciphertext[:8]
#             ciphertext = iv_and_ciphertext[8:]
#             cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)  # Use the stored 3DES key
#             decrypted = cipher.decrypt(ciphertext)
#             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
#         except Exception as e:
#             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

#     def rsa_decrypt(self, encrypted_text):
#         try:
#             ciphertext = base64.b64decode(encrypted_text)
#             cipher = PKCS1_OAEP.new(self.private_key)
#             decrypted = cipher.decrypt(ciphertext)
#             self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
#         except Exception as e:
#             self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

#     def generate_rsa_keys(self):
#         private_key = RSA.generate(2048)
#         public_key = private_key.publickey()
#         return private_key, public_key

#     def get_input_data(self):
#         if self.file_path.get():
#             try:
#                 with open(self.file_path.get(), "r") as file:
#                     return file.read()
#             except Exception as e:
#                 messagebox.showerror("خطا", f"خطا در خواندن فایل: {e}")
#                 return None
#         else:
#             return self.text_area.get("1.0", tk.END).strip()

#     def show_output(self, output):
#         self.output_text.config(state="normal")
#         self.output_text.delete("1.0", tk.END)
#         self.output_text.insert("1.0", output)
#         self.output_text.config(state="disabled")

#     def show_break_output(self, output):
#         self.hash_output_text.config(state="normal")
#         self.hash_output_text.delete("1.0", tk.END)
#         self.hash_output_text.insert("1.0", output)
#         self.hash_output_text.config(state="disabled")

#     def copy_output(self):
#         self.root.clipboard_clear()
#         self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
#         self.root.update()
#         messagebox.showinfo("کپی شد", "خروجی کپی شد!")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = CryptographyApp(root)
#     root.mainloop()


















import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Random import get_random_bytes
import base64
import itertools
import string
from collections import defaultdict
import threading

class CTMT:
    def __init__(self):
        self.precomputed_table = {}
        self.characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

    def precompute_hashes(self, max_length=5):
        for length in range(1, max_length + 1):
            for attempt in itertools.product(self.characters, repeat=length):
                password = ''.join(attempt)
                sha256_hash = SHA256.new(password.encode()).hexdigest()
                self.precomputed_table[sha256_hash] = password

    def crack_hash(self, hashed_value):
        return self.precomputed_table.get(hashed_value, "کلمه اصلی پیدا نشد.")

class CryptographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ابزار رمزنگاری و شکستن رمز")

        # Main container
        self.container = tk.Frame(root, padx=10, pady=10)
        self.container.pack(fill="both", expand=True)

        # Create the tab control
        self.tab_control = ttk.Notebook(self.container)

        # Create tabs
        self.encryption_tab = ttk.Frame(self.tab_control)
        self.breaking_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.encryption_tab, text="رمزنگاری و رمزگشایی")
        self.tab_control.add(self.breaking_tab, text="شکستن رمز")

        self.tab_control.pack(expand=1, fill="both")

        # Setup encryption tab
        self.setup_encryption_tab()

        # Setup breaking tab
        self.setup_breaking_tab()

        # Generate RSA keys (for asymmetric encryption)
        self.private_key, self.public_key = self.generate_rsa_keys()

        # Variable to store hashed value and keys
        self.hashed_value = None
        self.aes_key = None
        self.des_key = None
        self.dictionary = []  # For storing dictionary words
        self.rainbow_table = defaultdict(list)  # For storing rainbow table entries
        self.ctmt = CTMT()  # Create CTMT instance here

    def setup_encryption_tab(self):
        # Section: Algorithm Selection
        self.algorithm_frame = ttk.LabelFrame(self.encryption_tab, text="انتخاب الگوریتم", padding=(10, 10))
        self.algorithm_frame.pack(fill="x", pady=5)

        tk.Label(self.algorithm_frame, text="نوع رمزنگاری را انتخاب کنید:").grid(row=0, column=0, sticky="w", pady=5)
        self.crypto_type = tk.StringVar(value="متقارن")
        self.symmetric_radio = tk.Radiobutton(self.algorithm_frame, text="متقارن", variable=self.crypto_type, value="متقارن")
        self.symmetric_radio.grid(row=0, column=1, sticky="w")
        self.asymmetric_radio = tk.Radiobutton(self.algorithm_frame, text="نامتقارن", variable=self.crypto_type, value="نامتقارن")
        self.asymmetric_radio.grid(row=0, column=2, sticky="w")

        tk.Label(self.algorithm_frame, text="الگوریتم مورد نظر را انتخاب کنید:").grid(row=1, column=0, sticky="w", pady=5)
        self.algorithm = ttk.Combobox(
            self.algorithm_frame, values=[
                "AES", "3DES", "RSA", "SHA-256", "SHA-3"
            ], state="readonly"
        )
        self.algorithm.grid(row=1, column=1, sticky="w")
        self.algorithm.current(0)

        # Section: File/Data Input
        self.input_frame = ttk.LabelFrame(self.encryption_tab, text="ورودی فایل/داده", padding=(10, 10))
        self.input_frame.pack(fill="x", pady=5)

        tk.Label(self.input_frame, text="آپلود فایل:").grid(row=0, column=0, sticky="w", pady=5)
        self.file_path = tk.StringVar()
        self.file_entry = tk.Entry(self.input_frame, textvariable=self.file_path, width=40)
        self.file_entry.grid(row=0, column=1, sticky="w")
        self.browse_button = tk.Button(self.input_frame, text="انتخاب فایل", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, sticky="w")

        tk.Label(self.input_frame, text="متن خود را وارد کنید:").grid(row=1, column=0, sticky="w", pady=5)
        self.text_area = tk.Text(self.input_frame, height=5, width=50)
        self.text_area.grid(row=1, column=1, columnspan=2, sticky="w")

        # Section: Output Box
        self.output_frame = ttk.LabelFrame(self.encryption_tab, text="خروجی", padding=(10, 10))
        self.output_frame.pack(fill="x", pady=5)

        tk.Label(self.output_frame, text="نتیجه:").grid(row=0, column=0, sticky="w", pady=5)
        self.output_text = tk.Text(self.output_frame, height=5, width=50)
        self.output_text.grid(row=0, column=1, columnspan=2, sticky="w")
        self.output_text.config(state="disabled")  # Make it read-only

        self.copy_button = tk.Button(self.output_frame, text="کپی خروجی", command=self.copy_output)
        self.copy_button.grid(row=1, column=1, pady=5, sticky="e")

        # Section: Action Buttons
        self.action_frame = tk.Frame(self.encryption_tab, padx=10, pady=10)
        self.action_frame.pack(fill="x", pady=5)

        self.encrypt_button = tk.Button(self.action_frame, text="رمزگذاری", command=self.encrypt_data)
        self.encrypt_button.pack(side="left", padx=5)

        self.hash_button = tk.Button(self.action_frame, text="تولید هش", command=self.generate_hash)
        self.hash_button.pack(side="left", padx=5)

    def setup_breaking_tab(self):
        # Clear previous elements if any
            for widget in self.breaking_tab.winfo_children():
                widget.destroy()

        # Create a frame for the cryptanalysis tools
            self.cryptanalysis_frame = ttk.Frame(self.breaking_tab)
            self.cryptanalysis_frame.pack(fill="x", padx=10, pady=10)

        # Create buttons for attack categories
            self.break_hash_button = tk.Button(self.cryptanalysis_frame, text="شکستن هش", command=self.toggle_hash_attacks)
            self.break_hash_button.grid(row=0, column=0, padx=5, pady=5)

            self.break_password_button = tk.Button(self.cryptanalysis_frame, text="شکستن رمز", command=self.toggle_password_attacks)
            self.break_password_button.grid(row=0, column=1, padx=5, pady=5)

            self.ctmt_button = tk.Button(self.cryptanalysis_frame, text="CTMT", command=self.toggle_ctmt_attacks)
            self.ctmt_button.grid(row=0, column=2, padx=5, pady=5)

            # Frame for hash attacks
            self.hash_attacks_frame = ttk.Frame(self.breaking_tab)
            self.hash_attacks_frame.pack(fill="x", padx=10, pady=10)

            self.dictionary_attack_button = tk.Button(self.hash_attacks_frame, text="حمله دیکشنری", command=self.crack_hash_with_dictionary)
            self.dictionary_attack_button.pack(side="left", padx=5, pady=5)

            self.brute_force_button = tk.Button(self.hash_attacks_frame, text="حمله Brute Force", command=self.run_brute_force_attack)
            self.brute_force_button.pack(side="left", padx=5, pady=5)

            self.hash_attacks_frame.pack_forget()  # Initially hide this frame

            # Frame for password attacks
            self.password_attacks_frame = ttk.Frame(self.breaking_tab)
            self.password_attacks_frame.pack(fill="x", padx=10, pady=10)

            self.password_attacks_frame.pack_forget()  # Initially hide this frame

            # Frame for CTMT attacks
            self.ctmt_attacks_frame = ttk.Frame(self.breaking_tab)
            self.ctmt_attacks_frame.pack(fill="x", padx=10, pady=10)

            self.ctmt_button = tk.Button(self.ctmt_attacks_frame, text="حمله CTMT", command=self.crack_hash_with_ctmt)
            self.ctmt_button.pack(side="left", padx=5, pady=5)

            self.ctmt_attacks_frame.pack_forget()  # Initially hide this frame

    def toggle_hash_attacks(self):
        # Show or hide hash attack options
        if self.hash_attacks_frame.winfo_ismapped():
            self.hash_attacks_frame.pack_forget()
        else:
            self.hash_attacks_frame.pack(fill="x", padx=10, pady=10)
            self.password_attacks_frame.pack_forget()  # Hide other frames
            self.ctmt_attacks_frame.pack_forget()

    def toggle_password_attacks(self):
        # Show or hide password attack options
        if self.password_attacks_frame.winfo_ismapped():
            self.password_attacks_frame.pack_forget()
        else:
            self.password_attacks_frame.pack(fill="x", padx=10, pady=10)
            self.hash_attacks_frame.pack_forget()  # Hide other frames
            self.ctmt_attacks_frame.pack_forget()

    def toggle_ctmt_attacks(self):
        # Show or hide CTMT attack options
        if self.ctmt_attacks_frame.winfo_ismapped():
            self.ctmt_attacks_frame.pack_forget()
        else:
            self.ctmt_attacks_frame.pack(fill="x", padx=10, pady=10)
            self.hash_attacks_frame.pack_forget()  # Hide other frames
            self.password_attacks_frame.pack_forget()

    def run_another_attack(self):
    # Logic for another type of attack
        self.show_attack_output("عملکرد حملات دیگر در حال توسعه است.")

    def run_rainbow_table_attack(self):
        hashed_value = self.hash_input.get().strip()
        if not hashed_value:
            messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
            return
        
        # Implement rainbow table attack logic here
        # Assuming you have a precomputed rainbow table
        if hashed_value in self.rainbow_table:
            self.show_attack_output(f"کلمه اصلی: {self.rainbow_table[hashed_value]}")
        else:
            self.show_attack_output("کلمه اصلی پیدا نشد.")

    def show_attack_output(self, output):
        self.attack_output_text.config(state="normal")
        self.attack_output_text.delete("1.0", tk.END)
        self.attack_output_text.insert("1.0", output)
        self.attack_output_text.config(state="disabled")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def load_dictionary(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.dictionary = [line.strip() for line in file.readlines()]
                messagebox.showinfo("موفقیت", "دیکشنری با موفقیت بارگذاری شد.")
            except Exception as e:
                messagebox.showerror("خطا", f"خطا در بارگذاری دیکشنری: {e}")

    def encrypt_data(self):
        algorithm = self.algorithm.get()
        if algorithm == "AES":
            self.aes_encrypt()
        elif algorithm == "3DES":
            self.three_des_encrypt()
        elif algorithm == "RSA":
            self.rsa_encrypt()
        else:
            messagebox.showerror("خطا", f"رمزگذاری برای {algorithm} پشتیبانی نمی‌شود.")

    def generate_hash(self):
        algorithm = self.algorithm.get()
        data = self.get_input_data()
        if not data:
            messagebox.showerror("خطا", "لطفاً متنی برای هش کردن وارد کنید.")
            return
        if algorithm == "SHA-256":
            digest = SHA256.new()
        elif algorithm == "SHA-3":
            digest = SHA3_256.new()
        else:
            messagebox.showerror("خطا", f"هشینگ برای {algorithm} پشتیبانی نمی‌شود.")
            return
        
        digest.update(data.encode())
        self.hashed_value = digest.hexdigest()  # Store the hashed value
        self.show_output(self.hashed_value)
        self.populate_rainbow_table(data)  # Populate the rainbow table with the original data

    def populate_rainbow_table(self, original_data):
        # Add the original data and its hash to the rainbow table
        sha256_hash = SHA256.new(original_data.encode()).hexdigest()
        self.rainbow_table[sha256_hash].append(original_data)

    def check_hash(self):
        # Get the hashed value and comparison input
        hashed_value = self.hash_input.get().strip()
        comparison_input = self.compare_input.get().strip()

        if not hashed_value or not comparison_input:
            messagebox.showerror("خطا", "لطفاً هر دو متن را وارد کنید.")
            return

        # Check if the input matches the hash
        sha256_hash = SHA256.new(comparison_input.encode()).hexdigest()

        if sha256_hash == hashed_value:
            self.show_hash_break_output("متن صحیح است!")
        else:
            self.show_hash_break_output("متن صحیح نیست!")

    def crack_hash_with_dictionary(self):
        hashed_value = self.hash_input.get().strip()
        if not hashed_value:
            messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
            return
        
        if not self.dictionary:
            messagebox.showerror("خطا", "لطفاً ابتدا دیکشنری را بارگذاری کنید.")
            return

        found = False
        for word in self.dictionary:
            sha256_hash = SHA256.new(word.encode()).hexdigest()
            if sha256_hash == hashed_value:
                self.show_hash_break_output(f"کلمه اصلی: {word}")
                found = True
                break
        
        if not found:
            self.show_hash_break_output("کلمه اصلی پیدا نشد.")

    def run_brute_force_attack(self):
        hashed_value = self.hash_input.get().strip()
        if not hashed_value:
            messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
            return

        # Start the brute force attack in a separate thread
        threading.Thread(target=self.brute_force_attack, args=(hashed_value,)).start()

    def brute_force_attack(self, hashed_value):
        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        found = False
        for length in range(1, 6):  # Try lengths from 1 to 5
            for attempt in itertools.product(characters, repeat=length):
                password = ''.join(attempt)
                sha256_hash = SHA256.new(password.encode()).hexdigest()
                if sha256_hash == hashed_value:
                    self.show_hash_break_output(f"کلمه اصلی: {password}")
                    found = True
                    break  # Exit the loop if the password is found
            if found:
                break  # Exit outer loop if the password is found
        if not found:
            self.show_hash_break_output("کلمه اصلی پیدا نشد.")

    def precompute_hashes(self):
        self.ctmt.precompute_hashes(5)  # Precompute hashes for lengths up to 5
        messagebox.showinfo("موفقیت", "هش‌ها با موفقیت پیش‌محاسبه شدند!")

    def crack_hash_with_ctmt(self):
        hashed_value = self.ctmt_hash_input.get().strip()
        if not hashed_value:
            messagebox.showerror("خطا", "لطفاً هش را وارد کنید.")
            return

        result = self.ctmt.crack_hash(hashed_value)
        self.show_hash_break_output(result)

    def show_hash_break_output(self, output):
        self.hash_output_text.config(state="normal")
        self.hash_output_text.delete("1.0", tk.END)
        self.hash_output_text.insert("1.0", output)
        self.hash_output_text.config(state="disabled")

    def break_data(self):
        algorithm = self.break_algorithm.get()
        encrypted_text = self.break_input_text.get("1.0", tk.END).strip()
        try:
            if algorithm == "AES":
                self.aes_decrypt(encrypted_text)
            elif algorithm == "3DES":
                self.three_des_decrypt(encrypted_text)
            elif algorithm == "RSA":
                self.rsa_decrypt(encrypted_text)
            else:
                messagebox.showerror("خطا", f"شکستن رمز برای {algorithm} پشتیبانی نمی‌شود.")
        except Exception as e:
            messagebox.showerror("خطا", f"خطا در رمزگشایی: {str(e)}")

    def aes_encrypt(self):
        self.aes_key = get_random_bytes(32)  # 256-bit key
        iv = get_random_bytes(16)   # 128-bit IV
        data = self.get_input_data()
        if not data:
            messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
            return
        cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(data.encode())
        encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
        self.show_output(encrypted_base64)

    def three_des_encrypt(self):
        self.des_key = get_random_bytes(24)  # 192-bit key for 3DES
        iv = get_random_bytes(8)     # 64-bit IV
        data = self.get_input_data()
        if not data:
            messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
            return
        cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)
        ciphertext = cipher.encrypt(data.encode())
        encrypted_base64 = base64.b64encode(iv + ciphertext).decode()
        self.show_output(encrypted_base64)

    def rsa_encrypt(self):
        data = self.get_input_data()
        if not data:
            messagebox.showerror("خطا", "لطفاً متنی برای رمزگذاری وارد کنید.")
            return
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(data.encode())
        encrypted_base64 = base64.b64encode(ciphertext).decode()
        self.show_output(encrypted_base64)

    def aes_decrypt(self, encrypted_text):
        try:
            iv_and_ciphertext = base64.b64decode(encrypted_text)
            iv = iv_and_ciphertext[:16]
            ciphertext = iv_and_ciphertext[16:]
            cipher = AES.new(self.aes_key, AES.MODE_CFB, iv)  # Use the stored AES key
            decrypted = cipher.decrypt(ciphertext)
            self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
        except Exception as e:
            self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

    def three_des_decrypt(self, encrypted_text):
        try:
            iv_and_ciphertext = base64.b64decode(encrypted_text)
            iv = iv_and_ciphertext[:8]
            ciphertext = iv_and_ciphertext[8:]
            cipher = DES3.new(self.des_key, DES3.MODE_CFB, iv)  # Use the stored 3DES key
            decrypted = cipher.decrypt(ciphertext)
            self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
        except Exception as e:
            self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

    def rsa_decrypt(self, encrypted_text):
        try:
            ciphertext = base64.b64decode(encrypted_text)
            cipher = PKCS1_OAEP.new(self.private_key)
            decrypted = cipher.decrypt(ciphertext)
            self.show_break_output(decrypted.decode('utf-8', 'ignore'))  # Ignore errors
        except Exception as e:
            self.show_break_output(f"خطا در رمزگشایی: {str(e)}")

    def generate_rsa_keys(self):
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return private_key, public_key

    def get_input_data(self):
        if self.file_path.get():
            try:
                with open(self.file_path.get(), "r") as file:
                    return file.read()
            except Exception as e:
                messagebox.showerror("خطا", f"خطا در خواندن فایل: {e}")
                return None
        else:
            return self.text_area.get("1.0", tk.END).strip()

    def show_output(self, output):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", output)
        self.output_text.config(state="disabled")

    def show_break_output(self, output):
        self.hash_output_text.config(state="normal")
        self.hash_output_text.delete("1.0", tk.END)
        self.hash_output_text.insert("1.0", output)
        self.hash_output_text.config(state="disabled")

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
        self.root.update()
        messagebox.showinfo("کپی شد", "خروجی کپی شد!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptographyApp(root)
    root.mainloop()