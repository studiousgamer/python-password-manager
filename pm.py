#!/usr/bin/env python

import hashlib
import pyperclip
from dotenv import load_dotenv
import tkinter as tk

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

class App:
	def __init__(self, root):
		self.root = root
		self.root.title("PyPassword Manager")
		self.root.geometry("400x200")
		self.root.resizable(False, False)
		self.root.configure(background='#f0f0f0')

		tk.Button()


if __name__ == "__main__":
	root = tk.Tk()
	app = App(root)
	root.mainloop()
# main()