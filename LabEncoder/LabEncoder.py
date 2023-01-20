
import os
import time
from pngen import *

from tkinter import *
from tkinter import ttk
from tkinter.ttk import Style
from tkinter import filedialog as fd
from tkinter.messagebox import showinfo



fermat_numbers = [3, 5, 17, 257, 65537]

# --------------tkinter-generation-key-functions----------------


def submitbitesfunc():

    if (entry_1.get() != ""):
        input_bites = int(entry_1.get())
    else:
        return
    if (input_bites < 16):
        showinfo(title="Information", message="Numbers was not generated, too small bites!")
        return
    global p
    global q
    global eulerFuncVal
    global n

    p = getRandomPrime(input_bites)
    q = getRandomPrime(input_bites)
    n = p * q
    eulerFuncVal = (p-1)*(q-1)
    p, q = max(p, q), min(p, q)
    comboboxPE["state"] = 'readonly'
    saveKeysButton['state'] = "disabled"
    showinfo(title="Information", message="Primal numbers generated!")


def select_file_p():
    filetypes = (
        ('text files', '*.txt'),
        # ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    P['state'] = 'normal'
    P.delete(0, END)
    P.insert(END, str(filename))



def select_file_s():
    filetypes = (
        ('text files', '*.txt'),
        # ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    S['state'] = 'normal'
    S.delete(0, END)
    S.insert(END, str(filename))
    # S['state'] = 'readonly'



def gcd_(event):
    global m, d, a
    m, d, a = extended_gcd(int(comboboxPE.get()), int(eulerFuncVal))

    if(d < 0):
        d += eulerFuncVal;

    if (m != 1):
        showinfo(title="Information", message="Choose another variant!")
        openfileForPK['state'] = "disabled"
        S['state'] = "disabled"
        P['state'] = "disabled"
        openfileForSK['state'] = "disabled"
        saveKeysButton['state'] = "disabled"
    else:
        P['state'] = 'normal'
        S['state'] = 'normal'
        openfileForPK['state'] = "normal"
        openfileForSK['state'] = "normal"
        saveKeysButton['state'] = "normal"


def save_the_keys():
    left_brace = "{"
    right_brace = "}"
    back_slash = "\n"
    tabs = "\t"
    chosen_fermat_number = int(comboboxPE.get())

    stringp = f"RSAPublicKey ::= SEQUENCE {left_brace}{back_slash} modulus {n},{back_slash} publicExponent {chosen_fermat_number}{back_slash}{right_brace}{back_slash}"
    strings = f"RSAPrivateKey ::= SEQUENCE {left_brace}{back_slash}{tabs}modulus {n}{back_slash}{tabs}publicExponent {chosen_fermat_number},{back_slash}{tabs}privateExponent {d},{back_slash}{tabs}prime1 {p},{back_slash}{tabs}prime2 {q},{back_slash}{right_brace}{back_slash}"
    if (P.get() == "" or S.get() == ""):
       showinfo(title="Information", message="Choose files for keys!")
       return

    try: 
        public_key_file = open(P.get(), 'w')
        public_key_file.write(stringp)
        public_key_file.close()
        private_key_file = open(S.get(), 'w')
        private_key_file.write(strings)
        private_key_file.close()
        showinfo(title="Information", message="Keys saved!")
    except: 
        showinfo(title="Information", message="En error occured!")
        return;


# -----------------------------tkinter-encryption-functions---------------------------------------

def open_file_p():
    filetypes = (
        ('text files', '*.txt'),
        # ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    public_key_path.delete(0, END)
    public_key_path.insert(END, str(filename))
    # PublicKeyPath['state'] = 'readonly'


def open_file_enc():
    filetypes = (
        ('text files', '*.txt'),
        # ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    FilePath_E.delete(0, END)
    FilePath_E.insert(END, str(filename))
    if filename == "": return
    with open(filename, 'r') as f:
        text_for_encrypt.insert(END ,f.read())
    # FilePath_E['state'] = 'readonly'


def encrypt_file():
    left_brace = "{"
    right_brace = "}"
    backslash = "\n"
    tabs = "\t"
    encrypted_content = list()

    pkp = public_key_path.get()
    text_enc = text_for_encrypt.get("1.0", END)

    if pkp == "" or text_enc == "" :
        showinfo(title="Information", message="Choose the files!")
        return
    try:
        file_with_public_key = open(pkp, 'r').readlines()
    except:
        showinfo(title="Information", message="No such files")
        return

    filetypes = (
        ('Encrypted file', '.encrypted'),
        # ('All files', '*.*')
    )

    encrypted_file = fd.asksaveasfile(
        title='Open a file',
        defaultextension=".encrypted",
        initialdir=os.getcwd(),
        filetypes=filetypes)

    if encrypted_file == None: return

    try:
        public_key = int(list(map(str, file_with_public_key[1].split()))[
                        1].replace(",", ""))
        public_expn = int(list(map(str, file_with_public_key[2].split()))[1].replace(",", ""))
    except: 
           showinfo(title="Information", message="Wrong public key format!")
           return


    len_of_n = len(str(public_key))
    for i in text_enc:
        val = str(pow(ord(i), public_expn, public_key))
        tempstr = (len_of_n - len(val)) * "0"
        encrypted_content.append(tempstr + val)
    encrypted_content = ''.join(encrypted_content)
    string_enc = f"EncryptedData :: = SEQUENCE {left_brace}{backslash}{tabs}contentType TEXT {backslash}{tabs}contentEncryptionAlgorithmIdentifier rsaEncryption{backslash}{tabs}encryptedContent {encrypted_content}{backslash}{right_brace}{backslash}"

    encrypted_file.write(string_enc)
    encrypted_file.close()
    showinfo(title="Information", message="Encryption successful!")


# -------------------------tkinter-decryption-functions-----------------------------------------

def open_file_s():
    filetypes = (
        ('text files', '*.txt'),
        # ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    SecretKeyPath.delete(0, END)
    SecretKeyPath.insert(END, str(filename))
   # SecretKeyPath['state'] = 'readonly'


def open_file_decr():
    filetypes = (
        ('text files', '*.encrypted'),
        ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir=os.getcwd(),
        filetypes=filetypes)
    FilePath_D.delete(0, END)
    FilePath_D.insert(END, str(filename))
    # FilePath_D['state'] = 'readonly'


def decrypt_file():

    if SecretKeyPath.get() == "" or FilePath_D.get() == "" :
        showinfo(title="Information", message="Choose the files!")
        return

    try:
        file_with_keys = open(SecretKeyPath.get(), 'r').readlines()
        encrypted_file = open(FilePath_D.get(), 'r').readlines()
    except:
        showinfo(title="Information", message="No such files")
        return
    try:
        modulus = int(list(map(str, file_with_keys[1].split()))[1].replace(",", ""))
        private_exponent = int(list(map(str, file_with_keys[3].split()))[
                              1].replace(",", ""))
        len_of_n = len(str(modulus))
    except:
         showinfo(title="Information", message="Wrong keys format!")
         return
    encrypted_information = str(list(map(str, encrypted_file[3].split()))[1])
    chunks = [encrypted_information[i:i+len_of_n]
              for i in range(0, len(encrypted_information), len_of_n)]
    counter = 1
    decrypted_file = open(FilePath_D.get()[:-10] + "_decrypted" + ".txt", 'w')
    text_for_decrypt['state'] = 'normal'
    text_for_decrypt.delete('1.0', END)
    for e in chunks:
        #tic = time.perf_counter()
        decrypted_char = chr(pow(int(e), private_exponent,  modulus))  # MNOGO HAVAET OMG
        #toc = time.perf_counter()
        #print(toc - tic, elem, ", sec, number of elems: ", counter)
        decrypted_file.write(decrypted_char)
        text_for_decrypt.insert(END, decrypted_char)
        counter += 1
    decrypted_file.close()
    text_for_decrypt['state'] = 'disabled'
    showinfo(title="Information", message="Decription succesful!")
# --------------------------------tkinter-main-layout----------------------------------


window = Tk()
window.title("RSA encoding")
window.geometry('438x300')
window.resizable(False, False)
style = Style()
style.theme_create("MyStyle", parent="alt", settings={
    "TNotebook": {"configure": {"tabmargins": [0, 0, 0, 0]}},
    "TNotebook.Tab": {"configure": {"padding": [50, 0]}}})

style.theme_use("MyStyle")


tab_control = ttk.Notebook(window, width=250, height=250)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)
tab3 = ttk.Frame(tab_control)
tab_control.add(tab1, text='GenKey')
tab_control.add(tab2, text='Encrypt')
tab_control.add(tab3, text='Decrypt')

# -------------------------------tkinter-generation-keys-layout-----------------------------
lbl1 = ttk.Label(tab1, text='Size of prime number in bites',
                 width=30, font=("bold", 10))
lbl1.place(x=10, y=10)
entry_1 = Entry(tab1, width=10)
entry_1.place(x=210, y=10)

submitBitesButton = Button(tab1, text="Submit bites",
                           command = submitbitesfunc)
submitBitesButton.place_configure(x=300, y=7)

lbl2 = ttk.Label(tab1, text='Public exponent', width=30, font=("bold", 10))
lbl2.place(x=10, y=30)
var = StringVar()
comboboxPE = ttk.Combobox(tab1, textvariable=var, width=10)
comboboxPE['values'] = fermat_numbers
comboboxPE['state'] = 'disabled'
comboboxPE.place(x=120, y=30)
comboboxPE.bind("<<ComboboxSelected>>", gcd_)

openfileForPK = Button(tab1, text='File for public key',
                       command=select_file_p, width=20)
openfileForPK.place(x=10, y=150)

openfileForSK = Button(tab1, text='File for secret key',
                       command=select_file_s, width=20)
openfileForSK.place(x=10, y=120)

openfileForPK['state'] = "disabled"
openfileForSK['state'] = "disabled"

saveKeysButton = Button(tab1, text='Save keys',
                        command=save_the_keys, justify='center')
saveKeysButton.place(x=200, y=195)
saveKeysButton['state'] = "disabled"

P = Entry(tab1, width=30)
P.place(x=200, y=155)
P['state'] = 'readonly'
S = Entry(tab1, width=30)
S.place(x=200, y=125)
S['state'] = 'readonly'
# -----------------------------tkinter-encryption-layout---------------------------------
openfileForPK_E = Button(tab2, text='File for public key',
                         command=open_file_p, width=25)
openfileForPK_E.place(x=5, y=20)

openfileForENC = Button(tab2, text='Copy file information for encrypt',
                        command=open_file_enc, width=25)
openfileForENC.place(x=5, y=48)


public_key_path = Entry(tab2, width=37)
public_key_path.place(x=200, y=22)
# PublicKeyPath['state'] = 'readonly'

FilePath_E = Entry(tab2, width=37)
FilePath_E.place(x=200, y=50)
# FilePath_E['state'] = 'readonly'

text_for_encrypt = Text(tab2, height = 20, width = 25, bg = "white")
text_for_encrypt.pack(pady = (80, 35), padx = 5, fill = 'x')

encryptButton = Button(tab2, text='Encrypt',
                       command=encrypt_file, justify='center')
encryptButton.place(x=200, y=250)
# encryptButton['state'] = "disabled"

# -------------------------------tkinter-decryption-layout-------------------------------

openfileForSK_E = Button(tab3, text='File for secret key',
                         command=open_file_s, width=25)
openfileForSK_E.place(x=5, y=20)

openfileForDECR = Button(tab3, text='File for decrypt',
                         command=open_file_decr, width=25)
openfileForDECR.place(x=5, y=48)

SecretKeyPath = Entry(tab3, width=37)
SecretKeyPath.place(x=200, y=22)
# SecretKeyPath['state'] = 'readonly'

FilePath_D = Entry(tab3, width=37)
FilePath_D.place(x=200, y=50)
# FilePath_D['state'] = 'readonly'

text_for_decrypt = Text(tab3, height = 20, width = 25, bg = "white")
text_for_decrypt.pack(pady = (80, 35), padx = 5, fill = 'x')
text_for_decrypt['state'] = 'disabled'
encryptButton = Button(tab3, text='Decrypt file',
                       command=decrypt_file, justify='center')
encryptButton.place(x=200, y=250)

# -------------------------------main-loop-function-------------------------------
tab_control.pack(expand=1, fill='both')

window.mainloop()