#!/usr/bin/env python

import hashlib
import pyperclip
from dotenv import load_dotenv
import tkinter as tk
from tkinter import simpledialog, messagebox

import utils.add
import utils.retrieve
import utils.generate
from utils.dbconfig import dbconfig

load_dotenv()

# parser = argparse.ArgumentParser(description='Description')

# parser.add_argument('option', help='(a)dd / (e)xtract / (g)enerate')
# parser.add_argument("-s", "--name", help="Site name")
# parser.add_argument("-u", "--url", help="Site URL")
# parser.add_argument("-e", "--email", help="Email")
# parser.add_argument("-l", "--login", help="Username")
# parser.add_argument("--length", help="Length of the password to generate",type=int)
# parser.add_argument("-c", "--copy", action='store_true', help='Copy password to clipboard')

# args = parser.parse_args()

# def inputAndValidateMasterPassword():
# 	mp = getpass("MASTER PASSWORD: ")
# 	hashed_mp = hashlib.sha256(mp.encode()).hexdigest()

# 	db = dbconfig()
# 	cursor = db.cursor()
# 	query = "SELECT * FROM pm.secrets"
# 	cursor.execute(query)
# 	result = cursor.fetchall()[0]
# 	if hashed_mp != result[0]:
# 		printc("[red][!] WRONG! [/red]")
# 		return None

# 	return [mp,result[1]]


# def main():
# 	if args.option in ["add","a"]:
# 		if args.name is None or args.url is None or args.login is None:
# 			if args.name is None:
# 				printc("[red][!][/red] Site Name (-s) required ")
# 			if args.url is None:
# 				printc("[red][!][/red] Site URL (-u) required ")
# 			if args.login is None:
# 				printc("[red][!][/red] Site Login (-l) required ")
# 			return

# 		if args.email is None:
# 			args.email = ""

# 		res = inputAndValidateMasterPassword()
# 		if res is not None:
# 			utils.add.addEntry(res[0],res[1],args.name,args.url,args.email,args.login)


# 	if args.option in ["extract","e"]:
# 		res = inputAndValidateMasterPassword()

# 		search = {}
# 		if args.name is not None:
# 			search["sitename"] = args.name
# 		if args.url is not None:
# 			search["siteurl"] = args.url
# 		if args.email is not None:
# 			search["email"] = args.email
# 		if args.login is not None:
# 			search["username"] = args.login

# 		if res is not None:
# 			utils.retrieve.retrieveEntries(res[0],res[1],search,decryptPassword = args.copy)


# 	if args.option in ["generate","g"]:
# 		if args.length is None:
# 			printc("[red][+][/red] Specify length of the password to generate (--length)")
# 			return
# 		password = utils.generate.generatePassword(args.length)
# 		pyperclip.copy(password)
# 		printc("[green][+][/green] Password generated and copied to clipboard")

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


				print(search)

				result = utils.retrieve.retrieveEntries(result[0], result[1], search, decryptPassword=True)
				if result:
					messagebox.showinfo("Success", "Password extracted successfully")
				else:
					messagebox.showerror("Error", "Error extracting password")


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
		pass


if __name__ == "__main__":
	root = tk.Tk()
	app = App(root)
	root.mainloop()
# main()
