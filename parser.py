import tkinter as tk
from tkinter import simpledialog, Listbox, Button, messagebox, ttk
from requests import Session
from fake_useragent import UserAgent
from re import search
from pyperclip import copy
from pandas import DataFrame
from win10toast import ToastNotifier
from tkinter.filedialog import asksaveasfilename
from configparser import ConfigParser
from appdirs import user_data_dir
from os import path, getcwd, makedirs
import subprocess
import html
import sys

import configparser
from tkinter import simpledialog, Listbox, Button, messagebox

session = Session()

INI_FILE_PATH = path.join(user_data_dir()+"/Mantis Helper/", "credentials.ini")
INI_CONFIG_FILE = path.join(user_data_dir()+"/Mantis Helper/", "config.ini")
INI_SECTION = "Credentials"
if not path.exists(user_data_dir()+"/Mantis Helper/"):
    makedirs(user_data_dir()+"/Mantis Helper/")
def encrypt_message(message, key):
    encrypted_message = ""
    for char in message:
        encrypted_char = chr(ord(char) ^ key)
        encrypted_message += encrypted_char
    return encrypted_message

def decrypt_message(encrypted_message, key):
    decrypted_message = ""
    for char in encrypted_message:
        decrypted_char = chr(ord(char) ^ key)
        decrypted_message += decrypted_char
    return decrypted_message

key = 42

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = getcwd()
    return path.join(base_path, relative_path)


def load_credentials():
    if path.exists(INI_FILE_PATH):
        config = ConfigParser()
        config.read(INI_FILE_PATH)
        if INI_SECTION in config:
            username = config[INI_SECTION].get("username", "")
            password = decrypt_message(config[INI_SECTION].get("password", ""), key)
            entry_username.insert(0, username)
            entry_password.insert(0, password)


def setup_auth_link(link):
    if link[len(link) - 1] != "/":
        link += "/"
    link += "login.php"
    return link


def setup_search_link(link):
    if link[len(link) - 1] != "/":
        link += "/"
    link += "view.php?id="
    return link


def login():
    try:
        username = entry_username.get()
        password = entry_password.get()
        global session
        session = Session()
        if username and password:
            selected_server = server_combobox.get()
            link_auth = selected_server
            user = UserAgent().random
            headers = {
                "user-agent": user
            }
            data = {
                "username": username,
                "password": password
            }
            link_auth = setup_auth_link(link_auth)
            response = session.post(link_auth, data=data, headers=headers).text
            if "Logout" in response:
                login_status_label.configure(text="Logged in successfully!", fg="green")
                # Save credentials to INI file
                config = ConfigParser()
                config[INI_SECTION] = {"username": username, "password": encrypt_message(password, key)}
                with open(INI_FILE_PATH, "w") as config_file:
                    config.write(config_file)
            else:
                pattern = r'<div class="alert alert-danger"><p>(.*?)<\/p><\/div>'
                category_match = search(pattern, response)
                login_status_label.configure(text=category_match.group(1), fg="red")
        else:
            login_status_label.configure(text="Please enter username and password", fg="purple")
    except Exception as error:
        login_status_label.configure(text=str(error) , fg="purple")

def search_and_copy():
    issue_id = entry_issue_id.get()
    selected_server = server_combobox.get()
    if issue_id:
        issue_summary = setup_search_link(selected_server) + f"{issue_id}"
        issue_response = session.get(issue_summary).text

        pattern = r'<td class="bug-summary" colspan="5">(.*?)<\/td>'
        summary_match = search(pattern, issue_response)
        if summary_match:
            issue_summary = html.unescape(summary_match.group(1))
        else:
            issue_summary = "Summary not found"

        pattern = r'<td class="bug-category">(.*?)<\/td>'
        category_match = search(pattern, issue_response)
        if category_match:
            issue_category = html.unescape(category_match.group(1))
        else:
            issue_category = "Category not found"

        pattern = r'<td class="bug-project">(.*?)<\/td>'
        project_match = search(pattern, issue_response)
        if project_match:
            issue_project = html.unescape(project_match.group(1))
        else:
            issue_project = "Project not found"

        issue = f"{issue_summary}\t{issue_project}\t{issue_category}"
        copy(issue)
        # Display notification
        toaster = ToastNotifier()
        toaster.show_toast("Clipboard Notification", issue, duration=5, threaded=True)

        output_table.insert("", "end", values=(issue_summary, issue_project, issue_category))
    else:
        toaster = ToastNotifier()
        toaster.show_toast("Error", "Please enter issue ID", duration=5, threaded=True)


def export_to_excel():
    file_path = asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")])
    if file_path:
        data = []
        for item in output_table.get_children():
            values = output_table.item(item)["values"]
            data.append(values)
        df = DataFrame(data, columns=["Project", "Category", "Summary"])
        df.to_excel(file_path, index=False)


def on_server_select(event):
    if entry_username.get() and entry_password.get():
        login()


def copy_to_clipboard():
    data = []
    for item in output_table.get_children():
        values = output_table.item(item)["values"]
        data.append("\t".join(values))
    copied_data = "\n".join(data)
    copy(copied_data)


def save_credentials_on_exit():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        config = ConfigParser()
        config[INI_SECTION] = {"username": username, "password": encrypt_message(password)}
        with open(INI_FILE_PATH, "w") as config_file:
            config.write(config_file)


# Функція для отримання значення версії з файлу конфігурації
def get_app_version():
    config = ConfigParser()
    config.read(resource_path(INI_CONFIG_FILE))
    version = config.get("App", "version", fallback="Unknown")
    return version


def get_git_commit_count():
    try:
        output = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], universal_newlines=True)
        commit_count = int(output.strip())
        return commit_count
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def update_app_version():
    try:
        config = ConfigParser()
        config.read(resource_path(INI_CONFIG_FILE))
        if not config.has_section("App"):
            config.add_section("App")
        version = 0
        git_commit_count = get_git_commit_count()
        if git_commit_count is not None:
            version = f"1.0.{str(git_commit_count)}"

        config.set("App", "version", version)
        with open(INI_CONFIG_FILE, "w") as config_file:
            config.write(config_file)
    except:
        print("git didn't found")


def copy_version():
    version = get_app_version()
    version = f"Mantis Helper v{version}"
    copy(version)


# getting version though file.
update_app_version()
version = get_app_version()

# Create the main window
window = tk.Tk()
window.title(f"Mantis Helper v{version}")
# Calculate the screen width and height
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
# Calculate the x and y coordinates for the centered position
x = (screen_width - 650) // 2  # Adjust the form width as needed
y = (screen_height - 620) // 2  # Adjust the form height as needed

# Set the form geometry to be centered on the screen
window.geometry(f"650x620+{x}+{y}")

# Create the menu
menu_bar = tk.Menu(window)
window.config(menu=menu_bar)

# Create the File menu
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=window.quit)


def manage_servers():
    # Create a new window
    servers_window = tk.Toplevel(window)
    servers_window.title("Manage Servers")
    # Calculate the screen width and height
    screen_width = servers_window.winfo_screenwidth()
    screen_height = servers_window.winfo_screenheight()
    # Calculate the x and y coordinates for the centered position
    x = (screen_width - 300) // 2  # Adjust the form width as needed
    y = (screen_height - 200) // 2  # Adjust the form height as needed
    servers_window.geometry(f"320x300+{x}+{y}")

    # Create a frame to hold the servers listbox
    servers_frame = tk.Frame(servers_window)
    servers_frame.pack(fill=tk.BOTH, expand=True)

    # Create the servers listbox
    servers_listbox = Listbox(servers_frame)
    servers_listbox.pack(fill=tk.BOTH, expand=True)

    # Populate the listbox with values from config.ini
    servers = get_servers_from_config(server_combobox)
    for server in servers:
        servers_listbox.insert(tk.END, server)

    # Create buttons for adding and deleting servers
    buttons_frame = tk.Frame(servers_window)
    buttons_frame.pack()

    add_button = Button(buttons_frame, text="Add Server", command=lambda: add_server(servers_listbox))
    add_button.pack(side=tk.LEFT)

    delete_button = Button(buttons_frame, text="Delete Server", command=lambda: delete_server(servers_listbox))
    delete_button.pack(side=tk.LEFT)


def add_server(servers_listbox):
    # Відкрити просте вікно запиту для введення URL сервера
    server_url = simpledialog.askstring("Add Server", "Enter server URL:")
    if server_url:
        # Додати сервер до списку та зберегти у config.ini
        servers_listbox.insert(tk.END, server_url)
        save_servers_to_config(servers_listbox)
        if server_combobox:
            get_servers_from_config(server_combobox)


def delete_server(servers_listbox):
    # Отримати вибраний сервер зі списку
    selected_index = servers_listbox.curselection()
    if selected_index:
        selected_server = servers_listbox.get(selected_index)

        # Підтвердити видалення сервера за допомогою спливаючого вікна підтвердження
        confirmation = messagebox.askyesno("Delete Server", f"Are you sure you want to delete {selected_server}?")
        if confirmation:
            # Видалити сервер зі списку та зберегти у config.ini
            servers_listbox.delete(selected_index)
            save_servers_to_config(servers_listbox)
            get_servers_from_config(server_combobox)


def get_servers_from_config(server_combobox):
    config = configparser.ConfigParser()
    config.read(INI_CONFIG_FILE)
    if "Servers" in config:
        servers = config["Servers"]
        server_combobox.config(values=list(servers.values()))
        if len(list(servers.values())) > 0:
            server_combobox.current(0)
        return list(servers.values())
    else:
        return []


def save_servers_to_config(servers_listbox):
    config = configparser.ConfigParser()
    config["Servers"] = {}
    servers = servers_listbox.get(0, tk.END)
    for i, server in enumerate(servers):
        config["Servers"][f"Server{i + 1}"] = server

    with open(INI_CONFIG_FILE, "w") as config_file:
        config.write(config_file)


def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        window.destroy()


def clear_treeview():
    output_table.delete(*output_table.get_children())


menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Servers", command=manage_servers)

# Create the Version menu
version_menu = tk.Menu(menu_bar, tearoff=0)
version_menu.add_command(label="Copy Version", command=copy_version)
menu_bar.add_cascade(label="Version", menu=version_menu)

# Update the app version
update_app_version()

# Create the title label
title_label = tk.Label(window, text="Welcome to Mantis Helper", font=("Arial", 16))
title_label.pack(pady=10)

# Create the login table
login_table = ttk.Frame(window, padding=10)
login_table.pack()

# Create the username label and entry field
label_username = tk.Label(login_table, text="Username:")
label_username.grid(row=0, column=0, padx=5, pady=5)
entry_username = tk.Entry(login_table)
entry_username.grid(row=0, column=1, padx=5, pady=5)

# Create the password label and entry field
label_password = tk.Label(login_table, text="Password:")
label_password.grid(row=0, column=2, padx=5, pady=5)
entry_password = tk.Entry(login_table, show="*")
entry_password.grid(row=0, column=3, padx=5, pady=5)

load_credentials()  # Load credentials from INI file

# Create the login button
login_button = tk.Button(login_table, text="Log In to Mantis", fg="green", bd=1, relief="solid", borderwidth=1,
                         activebackground="green", activeforeground="white", command=login)
login_button.grid(row=0, column=4, padx=5, pady=5)

# Create the login status label
login_status_label = tk.Label(window, text="")
login_status_label.pack(pady=10)
login_status_label.configure(text="Please enter username and password or press login button", fg="purple")

# Create the search table
search_table = ttk.Frame(window, padding=10)
search_table.pack()

# Create the issue ID label and entry field
label_issue_id = tk.Label(search_table, text="Issue ID:")
label_issue_id.grid(row=0, column=0, padx=5, pady=5)
entry_issue_id = tk.Entry(search_table)
entry_issue_id.grid(row=0, column=1, padx=5, pady=5)

# Create the search and copy button
search_button = tk.Button(search_table, text="Search and Copy to Clipboard", fg="green", bd=1, relief="solid",
                          borderwidth=1, activebackground="green", activeforeground="white", command=search_and_copy)
search_button.grid(row=0, column=2, padx=5, pady=5)

# Create the output table
output_table = ttk.Treeview(window, columns=("Project", "Category", "Summary"), show="headings")
output_table.heading("Project", text="Project")
output_table.heading("Category", text="Category")
output_table.heading("Summary", text="Summary")
output_table.pack(padx=10, pady=6, fill="both", expand=True)

# Configure Treeview style
style = ttk.Style()
style.configure("Treeview", font=("Arial", 12))
style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

# Create the server selection combobox
server_combobox = ttk.Combobox(window, state="readonly")
amount = get_servers_from_config(server_combobox)
if len(amount) > 0:
    login()
server_combobox.bind("<<ComboboxSelected>>", on_server_select)
server_combobox.config(width=100)  # Adjust the width as needed
server_combobox.pack(padx=1, pady=1)

# Create the export button
export_button = tk.Button(window, text="Export as Excel", fg="blue", bd=1, relief="solid", borderwidth=1,
                          activebackground="blue", activeforeground="white", command=export_to_excel)
export_button.pack(side="left", padx=5, pady=5)

copy_button = tk.Button(window, text="Copy to Clipboard", fg="purple", bd=1, relief="solid", borderwidth=1,
                        activebackground="purple", activeforeground="white", command=copy_to_clipboard)
copy_button.pack(side="left", padx=5, pady=5)

clear_button = tk.Button(window, text="Clear History", fg="blue", bd=1, relief="solid", borderwidth=1,
                         activebackground="yellow", command=clear_treeview)
clear_button.pack(side="left", padx=5, pady=5)

window.protocol("WM_DELETE_WINDOW", save_credentials_on_exit)

window.protocol("WM_DELETE_WINDOW", on_closing)

# Start the Tkinter event loop
window.mainloop()
