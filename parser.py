import tkinter as tk
from tkinter import ttk
import requests
import fake_useragent
from bs4 import BeautifulSoup
import re
import pyperclip
import pandas as pd
session = requests.Session()
from win10toast import ToastNotifier
from tkinter.filedialog import asksaveasfilename


def login():
    username = entry_username.get()
    password = entry_password.get()

    link_auth = 'https://mantis-extern.boening.com/login.php'
    user = fake_useragent.UserAgent().random
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
    else:
        login_status_label.configure(text="Login failed!", fg="red")


def search_and_copy():
    issue_id = entry_issue_id.get()

    issue_summary = f"https://mantis-extern.boening.com/view.php?id={issue_id}"
    issue_response = session.get(issue_summary).text

    pattern = r'<td class="bug-summary" colspan="5">(.*?)<\/td>'
    summary_match = re.search(pattern, issue_response)
    if summary_match:
        issue_summary = summary_match.group(1)
    else:
        issue_summary = "Summary not found"

    pattern = r'<td class="bug-category">(.*?)<\/td>'
    category_match = re.search(pattern, issue_response)
    if category_match:
        issue_category = category_match.group(1)
    else:
        issue_category = "Category not found"

    pattern = r'<td class="bug-project">(.*?)<\/td>'
    project_match = re.search(pattern, issue_response)
    if project_match:
        issue_project = project_match.group(1)
    else:
        issue_project = "Project not found"

    issue = f"{issue_project}\t{issue_category}\t{issue_summary}"
    pyperclip.copy(issue)
    # Display notification
    toaster = ToastNotifier()
    toaster.show_toast("Clipboard Notification", issue, duration=5, threaded=True)

    output_table.insert("", "end", values=(issue_project, issue_category, issue_summary))


def export_to_excel():
    file_path = asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")])
    if file_path:
        data = []
        for item in output_table.get_children():
            values = output_table.item(item)["values"]
            data.append(values)
        df = pd.DataFrame(data, columns=["Project", "Category", "Summary"])
        df.to_excel(file_path, index=False)


# Create the main window
window = tk.Tk()
window.title("Mantis Helper")
window.geometry("620x490")
window.resizable(False, False)

# Create the title label
title_label = tk.Label(window, text="Welcome to Mantis Helper", font=("Arial", 16))
title_label.grid(row=0, columnspan=3, pady=10)

# Create the login table
login_table = ttk.Frame(window, padding=10)
login_table.grid(row=1, columnspan=3)

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

# Create the login button
login_button = tk.Button(login_table, text="Log In to Mantis", fg="green", bd=1, relief="solid", borderwidth=1,
                         activebackground="green", activeforeground="white", command=login)

login_button.grid(row=0, column=4, padx=5, pady=5)

# Create the login status label
login_status_label = tk.Label(window, text="")
login_status_label.grid(row=2, columnspan=3, pady=10)

# Create the search table
search_table = ttk.Frame(window, padding=10)
search_table.grid(row=3, columnspan=3)

# Create the issue ID label and entry field
label_issue_id = tk.Label(search_table, text="Issue ID:")
label_issue_id.grid(row=0, column=0, padx=5, pady=5)
entry_issue_id = tk.Entry(search_table)
entry_issue_id.grid(row=0, column=1, padx=5, pady=5)

# Create the search and copy button
search_button = tk.Button(search_table, text="Search and Copy to Clipboard", fg="green", bd=1, relief="solid",
                          borderwidth=1, activebackground="green", activeforeground="white", command=search_and_copy)

search_button.grid(row=0, column=2, padx=5, pady=5)

# Create the export button
export_button = tk.Button(window, text="Export as Excel", fg="blue", bd=1, relief="solid", borderwidth=1,
                          activebackground="blue", activeforeground="white", command=export_to_excel)
export_button.grid(row=6, columnspan=3, padx=5, pady=5, sticky="e")

# Create the output table
output_table = ttk.Treeview(window, columns=("Project", "Category", "Summary"), show="headings")
output_table.heading("Project", text="Project")
output_table.heading("Category", text="Category")
output_table.heading("Summary", text="Summary")
output_table.grid(row=5, columnspan=3, padx=10, pady=6)

# Configure Treeview style
style = ttk.Style()
style.configure("Treeview", font=("Arial", 12))
style.configure("Treeview.Heading", font=("Arial", 12, "bold"))
# Start the Tkinter event loop
window.mainloop()
