import tkinter as tk
from tkinter import filedialog
from algos import aes, chacha, threedes


def open_file_dialog():
    global selected_path
    path = path_var.get()
    if path == "file":
        selected_path = filedialog.askopenfilename(title="Select a file")
    else:
        selected_path = filedialog.askdirectory(title="Select a folder")

    if selected_path:
        file_path_var.set(selected_path)


def perform_action():
    action = action_var.get()
    password = password_var.get()
    selected_value = selected_option.get()

    encryption_functions = {
        "AES": (aes.encrypt, aes.decrypt),
        "ChaCha20": (chacha.encrypt, chacha.decrypt),
        "3DES": (threedes.encrypt, threedes.decrypt)
    }

    if selected_value in encryption_functions:
        encrypt_func, decrypt_func = encryption_functions[selected_value]
        if action == "encryption":
            encrypt_func(password, selected_path)
        elif action == "decryption":
            decrypt_func(password, selected_path)

    root.destroy()


def toggle_password_visibility():
    if show_password_var.get() == 1:
        password_entry.config(show="")
    else:
        password_entry.config(show="*")


root = tk.Tk()
root.title("Encryption Program")
root.geometry("350x400")

selected_path = ""
file_path_var = tk.StringVar()
password_var = tk.StringVar()
show_password_var = tk.IntVar()
action_var = tk.StringVar()
action_var.set("encryption")
path_var = tk.StringVar()
path_var.set("file")

label = tk.Label(root, text="Select an action:")
label.pack(pady=(15, 5))

action_frame = tk.Frame(root)
action_frame.pack()

encryption_radio = tk.Radiobutton(action_frame, text="Encryption", variable=action_var, value="encryption")
encryption_radio.pack(side="left", padx=10)

decryption_radio = tk.Radiobutton(action_frame, text="Decryption", variable=action_var, value="decryption")
decryption_radio.pack(side="left", padx=10)

options = ["Select an Encryption Algorithm", "AES", "ChaCha20", "3DES"]
selected_option = tk.StringVar(value=options[0])

dropdown_menu = tk.OptionMenu(root, selected_option, *options)
dropdown_menu.pack(pady=(9,2))

label = tk.Label(root, text="Select a path:")
label.pack(pady=(15, 5))

path_type_frame = tk.Frame(root)
path_type_frame.pack()

file_radio = tk.Radiobutton(path_type_frame, text="File", variable=path_var, value="file")
file_radio.pack(side="left", padx=10)

folder_radio = tk.Radiobutton(path_type_frame, text="Folder", variable=path_var, value="folder")
folder_radio.pack(side="left", padx=10)

browse_button = tk.Button(root, text="Browse", command=open_file_dialog)
browse_button.pack(pady=(15, 0))
browse_button.pack(padx=(0, 10))

file_path_textbox = tk.Entry(root, textvariable=file_path_var, state="readonly", width=50)
file_path_textbox.pack(pady=10)

password_label = tk.Label(root, text="Enter Password:")
password_label.pack()

password_entry = tk.Entry(root, textvariable=password_var, show="*")
password_entry.pack(pady=10)

show_password_checkbox = tk.Checkbutton(root, text="Show Password", variable=show_password_var,
                                        command=toggle_password_visibility)
show_password_checkbox.pack()

action_button = tk.Button(root, text="Perform Action", command=perform_action)
action_button.pack(pady=5)

root.mainloop()
