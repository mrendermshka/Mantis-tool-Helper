import tkinter as tk
from tkinter import ttk
from requests import Session
from fake_useragent import UserAgent
from re import search
from pyperclip import copy
from pandas import DataFrame
from win10toast import ToastNotifier
from tkinter.filedialog import asksaveasfilename
from configparser import ConfigParser
from appdirs import user_data_dir
from os import path, getcwd
import subprocess
import html
import sys

session = Session()

INI_FILE_PATH = path.join(user_data_dir(), "credentials.ini")
INI_SECTION = "Credentials"

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
            password = config[INI_SECTION].get("password", "")
            entry_username.insert(0, username)
            entry_password.insert(0, password)


def login():
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
        response = session.post(link_auth, data=data, headers=headers).text
        if "Logout" in response:
            login_status_label.configure(text="Logged in successfully!", fg="green")
            # Save credentials to INI file
            config = ConfigParser()
            config[INI_SECTION] = {"username": username, "password": password}
            with open(INI_FILE_PATH, "w") as config_file:
                config.write(config_file)
        else:
            pattern = r'<div class="alert alert-danger"><p>(.*?)<\/p><\/div>'
            category_match = search(pattern, response)
            login_status_label.configure(text=category_match.group(1), fg="red")
    else:
        login_status_label.configure(text="Please enter username and password", fg="purple")


def search_and_copy():
    issue_id = entry_issue_id.get()

    if issue_id:
        issue_summary = f"https://mantis-extern.boening.com/view.php?id={issue_id}"
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

        issue = f"{issue_project}\t{issue_category}\t{issue_summary}"
        copy(issue)
        # Display notification
        toaster = ToastNotifier()
        toaster.show_toast("Clipboard Notification", issue, duration=5, threaded=True)

        output_table.insert("", "end", values=(issue_project, issue_category, issue_summary))
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
        config[INI_SECTION] = {"username": username, "password": password}
        with open(INI_FILE_PATH, "w") as config_file:
            config.write(config_file)


# Функція для отримання значення версії з файлу конфігурації
def get_app_version():
    config = ConfigParser()
    config.read(resource_path("config.ini"))
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
        config.read(resource_path("config.ini"))
        if not config.has_section("App"):
            config.add_section("App")
        version = 0
        git_commit_count = get_git_commit_count()
        if git_commit_count is not None:
            version = f"1.0.{str(git_commit_count)}"

        config.set("App", "version", version)
        with open("config.ini", "w") as config_file:
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
window.geometry("650x620")

# Create the menu
menu_bar = tk.Menu(window)
window.config(menu=menu_bar)

# Create the File menu
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=window.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

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
server_combobox = ttk.Combobox(window, values=["https://bugtracker.boening.com/login.php",
                                               "https://mantis-extern.boening.com/login.php",
                                               "https://pr20.boening.com/login.php"],
                               state="readonly")
server_combobox.current(1)
server_combobox.bind("<<ComboboxSelected>>", on_server_select)
server_combobox.pack(padx=5, pady=5)

# Create the export button
export_button = tk.Button(window, text="Export as Excel", fg="blue", bd=1, relief="solid", borderwidth=1,
                          activebackground="blue", activeforeground="white", command=export_to_excel)
export_button.pack(side="left", padx=5, pady=5)

copy_button = tk.Button(window, text="Copy to Clipboard", fg="purple", bd=1, relief="solid", borderwidth=1,
                        activebackground="purple", activeforeground="white", command=copy_to_clipboard)
copy_button.pack(side="left", padx=5, pady=5)

window.protocol("WM_DELETE_WINDOW", save_credentials_on_exit)
# Start the Tkinter event loop
window.mainloop()
