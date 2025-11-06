import base64
import binascii
import sys
import argparse

# 尝试导入PyQt6。如果失败，只有在用户请求GUI时才抛出错误。
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QRadioButton, QLineEdit, QTextEdit, QPushButton, QLabel, QMessageBox,
        QCheckBox
    )

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False


def unicode_vigenere_encrypt(plaintext: str, key: str, use_base64: bool = True):
    """
    Vigenère Cipher encrypt
    :param plaintext: the text that you want to encrypt
    :param key: encrypt key
    :param use_base64: use base64 encode the output or not
    :return: encrypted text
    """
    encrypted_text_raw = ""
    key_index = 0

    if not key:
        raise ValueError("Key cannot be empty.")

    for char in plaintext:
        p_code = ord(char)
        k_code = ord(key[key_index % len(key)])
        encrypted_code = p_code + k_code
        encrypted_text_raw += chr(encrypted_code)
        key_index += 1

    if use_base64:
        raw_bytes = encrypted_text_raw.encode('utf-8')
        base64_bytes = base64.b64encode(raw_bytes)
        return base64_bytes.decode('utf-8')
    else:
        return encrypted_text_raw


def unicode_vigenere_decrypt(ciphertext: str, key: str, use_base64: bool = True):
    """
    Vigenère Cipher decrypt
    :param ciphertext: encrypted text
    :param key: encrypt key
    :param use_base64: use base64 encode the output or not
    :return: decrypted text
    :raises ValueError: Key is empty.
    :raises SyntaxError: use_base64 is True and ciphertext is not valid base64 encoded text
    """
    raw_ciphertext = ""

    if not key:
        raise ValueError("Key cannot be empty.")

    if use_base64:
        try:
            base64_bytes = ciphertext.encode('utf-8')
            raw_bytes = base64.b64decode(base64_bytes)
            raw_ciphertext = raw_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            raise SyntaxError("Ciphertext is not valid base64 encoded text for the given encoding.")
    else:
        raw_ciphertext = ciphertext

    decrypted_text = ""
    key_index = 0

    for char in raw_ciphertext:
        c_code = ord(char)
        k_code = ord(key[key_index % len(key)])
        decrypted_code = c_code - k_code
        decrypted_text += chr(decrypted_code)
        key_index += 1

    return decrypted_text


# --- GUI Implementation ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unicode Vigenère Cipher")
        self.setGeometry(100, 100, 500, 400)

        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Mode selection
        mode_layout = QHBoxLayout()
        self.rb_encrypt = QRadioButton("Encrypt")
        self.rb_decrypt = QRadioButton("Decrypt")
        self.rb_encrypt.setChecked(True)
        mode_layout.addWidget(self.rb_encrypt)
        mode_layout.addWidget(self.rb_decrypt)
        main_layout.addLayout(mode_layout)

        # Key input
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Key:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter your secret key")
        key_layout.addWidget(self.key_input)
        main_layout.addLayout(key_layout)

        # Base64 checkbox
        self.cb_base64 = QCheckBox("Use Base64 Encoding")
        self.cb_base64.setChecked(True)
        main_layout.addWidget(self.cb_base64)

        # Input text area
        main_layout.addWidget(QLabel("Input:"))
        self.input_text = QTextEdit()
        main_layout.addWidget(self.input_text)

        # Process button
        self.process_button = QPushButton("Process")
        self.process_button.clicked.connect(self.process_text)
        main_layout.addWidget(self.process_button)

        # Output text area
        main_layout.addWidget(QLabel("Output:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)

    def process_text(self):
        key = self.key_input.text()
        input_text = self.input_text.toPlainText()
        use_base64 = self.cb_base64.isChecked()

        if not key:
            QMessageBox.warning(self, "Warning", "Please enter a key.")
            return
        if not input_text:
            QMessageBox.warning(self, "Warning", "Input text cannot be empty.")
            return

        try:
            if self.rb_encrypt.isChecked():
                result = unicode_vigenere_encrypt(input_text, key, use_base64)
            else:
                result = unicode_vigenere_decrypt(input_text, key, use_base64)
            self.output_text.setText(result)
        except (ValueError, SyntaxError) as e:
            QMessageBox.critical(self, "Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "An Unexpected Error Occurred", str(e))


def run_gui():
    """Starts the PyQt6 GUI application."""
    if not PYQT6_AVAILABLE:
        print("Error: PyQt6 is not installed. Please run 'pip install PyQt6' to use the GUI.", file=sys.stderr)
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


# --- CLI Implementation ---
def run_cli():
    """Starts the interactive Command Line Interface."""
    help_text = """:(exit|quit|q)\t\t\t-> quit
:(e|enc|encrypt)\t\t-> encrypt mode
:(d|dec|decrypt)\t\t-> decrypt mode
:(setkey|keyset)\t\t-> set encrypt/decrypt key
:(key|showkey)\t\t\t-> print current key"""
    key = ""
    mode = 0  # 0: None, 1: Encrypt, 2: Decrypt

    while True:
        mode_str = ['input :h for help', 'encrypt', 'decrypt'][mode]
        prompt = f"{mode_str}, key status: {bool(key)}> "
        user_input = input(prompt).strip()

        if user_input.startswith(':'):
            command = user_input.lower()[1:].strip()
            if command in ['setkey', 'keyset']:
                key = input('set new key: ')
            elif command in ['key', 'showkey']:
                print(f"Current key: {key}")
            elif command in ['exit', 'quit', 'q']:
                break
            elif command in ['e', 'enc', 'encrypt']:
                mode = 1
            elif command in ['d', 'dec', 'decrypt']:
                mode = 2
            elif command in ['h', 'help']:
                print(help_text)
            else:
                print(f"Unknown command: {command}")
        elif mode == 0 or not key:
            if mode == 0:
                print('Please set a mode first (:e or :d).')
            if not key:
                print('Please set a key first (:setkey).')
        elif mode == 1:  # Encrypt
            try:
                print(unicode_vigenere_encrypt(user_input, key))
            except ValueError as e:
                print(f"Error: {e}")
        elif mode == 2:  # Decrypt
            try:
                print(unicode_vigenere_decrypt(user_input, key))
            except (ValueError, SyntaxError) as e:
                print(f"Error: {e}")


# --- Main Execution ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt text using Unicode Vigenère cipher.")
    parser.add_argument('--gui', action='store_true', help='Launch the graphical user interface.')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--encrypt', metavar='PLAINTEXT', type=str, help='Plaintext to encrypt.')
    group.add_argument('-d', '--decrypt', metavar='CIPHERTEXT', type=str, help='Ciphertext to decrypt.')

    parser.add_argument('-k', '--key', type=str, help='The secret key for encryption/decryption.')
    parser.add_argument('--no-base64', action='store_true', help='Disable Base64 encoding for output.')

    args = parser.parse_args()

    use_base64_arg = not args.no_base64

    if args.gui:
        run_gui()
    elif args.encrypt or args.decrypt:
        if not args.key:
            parser.error("--key is required for encryption/decryption.")

        try:
            if args.encrypt:
                result = unicode_vigenere_encrypt(args.encrypt, args.key, use_base64_arg)
                print(result)
            elif args.decrypt:
                result = unicode_vigenere_decrypt(args.decrypt, args.key, use_base64_arg)
                print(result)
        except (ValueError, SyntaxError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        run_cli()