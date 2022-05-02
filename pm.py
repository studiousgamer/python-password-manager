import hashlib
from dotenv import load_dotenv
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk

import utils.add
import utils.retrieve
import utils.generate
from utils.dbconfig import dbconfig

load_dotenv()

class Popup:
	def __init__(self, root, name, options: list, askMastePass=False):
		self.root = root
		self.name = name
		self.options = options
		self.askMastePass = askMastePass

		self.window = tk.Toplevel(root)
		self.window.wm_title(self.name)

		height = 95
		for option in self.options:
			height += 30

		self.window.geometry(f"400x{height}")
		self.inputs = {}

		tk.Label(self.window, text=self.name, justify=tk.CENTER, font=(
			"Helvetica", 20)).place(x=0, y=15, width=400, height=30)

		for index, name in enumerate(self.options):
			tk.Label(self.window, text=name).place(
				x=10, y=55 + (index * 30), width=100, height=25)
			self.inputs[name.split(" ")[0]] = tk.Entry(self.window)
			self.inputs[name.split(" ")[0]].place(
				x=120, y=55 + (index * 30), width=200, height=25)

		# ok and cancel buttons
		tk.Button(self.window, text="OK", command=self.ok).place(
			x=200, y=height - 50, width=100, height=25)
		tk.Button(self.window, text="Cancel", command=self.window.destroy).place(
			x=300, y=height - 50, width=100, height=25)

	def ok(self):
		if self.askMastePass:
			password = simpledialog.askstring(
				"MASTER PASSWORD", "Enter master password:")
			if password is None:
				return
			hashed_mp = hashlib.sha256(password.encode()).hexdigest()
			db = dbconfig()
			cursor = db.cursor()
			query = "SELECT * FROM pm.secrets"
			cursor.execute(query)
			result = cursor.fetchall()[0]
			if hashed_mp != result[0]:
				messagebox.showerror("Error", "Wrong master password")
				return

			if self.name == "Add Password":
				for input_ in self.inputs.values():
					content = input_.get()
					if content.replace(" ", "") == "":
						messagebox.showerror("Error", "Empty fields")
						return
				result = utils.add.addEntry(result[0], result[1], self.inputs["Site_Name"].get(), 
						self.inputs["Site_URL"].get(), self.inputs["Email"].get(), self.inputs["Username"].get(), 
						self.inputs["Password"].get())
				if result:
					messagebox.showinfo("Success", "Password added successfully")
				else:
					messagebox.showerror("Error", "Error adding password")

			if self.name == "Retrieve Password":
				search = {}
				site_name = self.inputs["Site_Name"].get()
				url = self.inputs["Site_URL"].get()
				email = self.inputs["Email"].get()
				username = self.inputs["Username"].get()
				
				if site_name not in ["", None]:
					search["sitename"] = site_name
				if url not in ["", None]:
					search["siteurl"] = url
				if email not in ["", None]:
					search["email"] = email
				if username not in ["", None]:
					search["username"] = username

				result = utils.retrieve.retrieveEntries(result[0], result[1], search, decryptPassword=True)
				if type(result[1]) is list:
					passDisplay = tk.Toplevel(self.root)
					passDisplay.wm_title("Password")
					passDisplay.geometry("470x200")
					tk.Label(passDisplay, text="Retrieved Passwords", justify=tk.CENTER, font=(
						"Helvetica", 20)).place(x=0, y=15, width=470, height=30)
					treeview = ttk.Treeview(passDisplay)
					treeview.place(x=10, y=50, width=450, height=140)
					treeview["columns"] = ("sitename", "siteurl", "email", "username")

					treeview.heading("#0", text="ID")
					treeview.column("#0", width=50)
					treeview.heading("sitename", text="Site Name")
					treeview.column("sitename", width=100)
					treeview.heading("siteurl", text="Site URL")
					treeview.column("siteurl", width=100)
					treeview.heading("email", text="Email")
					treeview.column("email", width=100)
					treeview.heading("username", text="Username")
					treeview.column("username", width=100)

					for index, entry in enumerate(result[1]):
						treeview.insert("", index, text=str(index), values=(entry[0], entry[1], entry[2], entry[3]))
				else:
					messagebox.showinfo(result[0], result[1])


class App:
	def __init__(self, root):
		self.root = root
		self.root.title("PyPassword Manager")
		self.root.geometry("400x200")
		self.root.resizable(False, False)
		self.root.configure(background='#f0f0f0')

		tk.Label(self.root, text="PyPassword Manager", font=("Helvetica", 25),
				 bg='#f0f0f0', justify=tk.CENTER).place(x=0, y=40, width=400, height=50)

		tk.Button(self.root, text="Add", command=self.add).place(
			x=30, y=110, width=100, height=25)
		tk.Button(self.root, text="Retrieve", command=self.retrieve).place(
			x=150, y=110, width=100, height=25)
		tk.Button(self.root, text="Generate", command=self.generate).place(
			x=270, y=110, width=100, height=25)

	def add(self):
		Popup(self.root, "Add Password", [
			  "Site_Name", "Site_URL", "Email", "Username (*)", "Password (*)"], askMastePass=True)

	def retrieve(self):
		Popup(self.root, "Retrieve Password", [
			  "Site_Name", "Site_URL", "Email", "Username"], askMastePass=True)

	def generate(self):
		utils.generate.Generator(self.root)


if __name__ == "__main__":
	root = tk.Tk()
	app = App(root)
	root.mainloop()
# main()
