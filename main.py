# Secret Notes
from tkinter import *
from tkinter import messagebox
import base64

# UI General
window = Tk()
window.title("Secret Notes")
window.config(padx=50, pady=50)
FONT = ("Verdana", 10, "normal")

# Functions


def save():
    title = titleEntry.get()
    message = inputText.get("1.0", END)
    masterSecret = masterSecretInput.get()

    if len(title) == 0 or len(message) == 0 or len(masterSecret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info!")
    else:
        #encryption:
        messageEncrypted = encode(masterSecret, message)
        try:
            with open("mysecret.txt", "a") as data_file:  # a = append
                data_file.write(f"\n{title}\n{messageEncrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:  # w = write
                data_file.write(f"\n{title}\n{messageEncrypted}")
        finally:
            titleEntry.delete(0, END)
            masterSecretInput.delete(0, END)
            inputText.delete("1.0", END)


def decrypt():
    messageEncrypted = inputText.get("1.0", END)
    masterSecret = masterSecretInput.get()

    if len(messageEncrypted) == 0 or len(masterSecret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decryptedMessage = decode(masterSecret, messageEncrypted)
            inputText.delete("1.0", END)
            inputText.insert("1.0", decryptedMessage)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")


# code, decode
# copied from https://stackoverflow.com/questions/2490334/simple-way-to-encode-a-string-according-to-a-password

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

# copy end
# Photo


photo = PhotoImage(file="icon.png")
photoLabel = Label(image=photo)
photoLabel.pack()

# UI
titleInfoLabel = Label(text="enter your title", font=FONT)
titleInfoLabel.pack()

titleEntry = Entry(width=30)
titleEntry.pack()

inputInfoLabel = Label(text="enter your secret", font=FONT)
inputInfoLabel.pack()

inputText = Text(width=20, height=10)
inputText.pack()

masterSecretLabel = Label(text="enter master key", font=FONT)
masterSecretLabel.pack()

masterSecretInput = Entry(width=30)
masterSecretInput.pack()

saveButton = Button(text="save & encrypt", command=save)  # command will be added -> OK added!
saveButton.pack()

decryptButton = Button(text="decrypt", command=decrypt)  # command will be added -> OK added!
decryptButton.pack()

window.mainloop()
