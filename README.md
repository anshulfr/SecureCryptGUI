# SecureCryptGUI

This is a simple GUI-based encryption program developed using Python's Tkinter library. The program allows users to encrypt and decrypt files using various encryption algorithms.

## Features

- Encrypt and decrypt files/folders using different encryption algorithms.
- Choose between AES, ChaCha20, and 3DES encryption methods.
- User-friendly interface for selecting files or folders.
- Supports both encryption and decryption actions.

## Requirements

- Python 3.x
- `tkinter`
- `cryptography`

## Getting Started

1. Clone this repository to your local machine:

```
git clone https://github.com/anshulnegii/SecureCryptGUI.git
```

2. Navigate to the project directory:

```
cd SecureCryptGUI
```

3. Install any necessary dependencies:

```
# Example using pip
pip install -r requirements.txt
```

4. Run the application:

```
python -B main.py
```

## Usage

1. Upon running the application, a GUI window will appear.
2. Select an action (encryption or decryption).
3. Choose an encryption algorithm from the dropdown menu (AES, ChaCha20, 3DES).
4. Select whether to work with a file or folder.
5. Browse and select the file/folder you want to process.
6. Enter the encryption/decryption password.
7. Click the "Perform Action" button to initiate the encryption/decryption process.
Contributions are welcome! If you'd like to enhance the project or fix any issues, feel free to create pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
