
import tkinter as tk
import tkinter.font as tkFont
from tkinter import messagebox
import random
import pyperclip


class Generator:
	def __init__(self, root):
		root = tk.Toplevel(root)
		root.title("Password Generator")
		root.geometry("350x250")
		root.resizable(width=False, height=False)

		AppLabel = tk.Label(root, text="Password Generator", font=tkFont.Font(family="Helvetica", size=18, weight="bold"), fg="#000000")
		AppLabel.place(x=50, y=25)
		self.capitalVar = tk.IntVar()
		self.capital = tk.Checkbutton(root, text="Capital Letters", font=tkFont.Font(family="Helvetica", size=12), fg="#000000", justify="left", variable=self.capitalVar)
		self.capital.place(x=20, y=80, width=150, height=25)
		self.smallVar = tk.IntVar()
		self.small = tk.Checkbutton(root, text="Small Letters", font=tkFont.Font(family="Helvetica", size=12), fg="#000000", justify="left", variable=self.smallVar)
		self.small.place(x=185, y=80, width=150, height=25)
		self.numbersVar = tk.IntVar()
		self.numbers = tk.Checkbutton(root, text="Numbers", font=tkFont.Font(family="Helvetica", size=12), fg="#000000", justify="left", variable=self.numbersVar)
		self.numbers.place(x=20, y=110, width=150, height=25)
		self.specialVar = tk.IntVar()
		self.special = tk.Checkbutton(root, text="Special Characters", font=tkFont.Font(family="Helvetica", size=12), fg="#000000", justify="left", variable=self.specialVar)
		self.special.place(x=175, y=110, width=165, height=25)
		self.length = tk.Entry(root, font=tkFont.Font(family="Helvetica", size=12), fg="#000000")
		self.length.place(x=100, y=150, width=200, height=25)
		self.length.insert(0, "8")
		self.lengthLabel = tk.Label(root, text="Length", font=tkFont.Font(family="Helvetica", size=12), fg="#000000")
		self.lengthLabel.place(x=20, y=150, width=60, height=25)
		self.generate = tk.Button(root, text="Generate", font=tkFont.Font(family="Helvetica", size=12), fg="#000000", command=self.generatePassword)
		self.generate.place(x=100, y=180, width=200, height=25)
		self.password = tk.Entry(root, font=tkFont.Font(family="Helvetica", size=12))
		self.password.place(x=100, y=210, width=200, height=25)

	def generatePassword(self):
		password = ""
		if self.capitalVar.get() == 1:
			password += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		if self.smallVar.get() == 1:
			password += "abcdefghijklmnopqrstuvwxyz"
		if self.numbersVar.get() == 1:
			password += "0123456789"
		if self.specialVar.get() == 1:
			password += "!@#$%^&*()_+-=[]{}|;':,./<>?"
		length = int(self.length.get())
		try:
			password = "".join(random.sample(password, length))
			self.password.delete(0, tk.END)
			self.password.insert(0, password)
			pyperclip.copy(password)
			messagebox.showinfo("Password Generator", "Password copied to clipboard")
		except Exception as e:
			print(e)
			messagebox.showerror("Invalid","Select Checkbox")
