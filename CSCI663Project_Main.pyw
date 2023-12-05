import logging
import time
from tkinter import *
import tkinter as tk
from tkinter import filedialog
import os

logging.basicConfig(level=logging.DEBUG,
                    format=' %(asctime)s -  %(levelname)s -  %(message)s')


# RSA implemented by Gilberto Andres Guerra Gonzalez
try:
    import CSCI663Project_RSA as rsa
except Exception as e:
    logging.critical(e)
    exit(1)

# AES implemented by Jose Nazareno Torres Ambrosio
try:
    import CSCI663Project_AES as aes
except Exception as e:
    logging.critical(e)
    exit(1)


# simple class that is only to circumvent not being able to get return value from tkinter button command function
class RSAParameterGenerator:
    def __init__(self):
        self.n, self.public_key, self.private_key = rsa.generate_keys(512)

    def get_keys(self):
        return (self.n, self.public_key, self.private_key)

    def generate_new_keys(self, pqlength):
        self.n, self.public_key, self.private_key = rsa.generate_keys(pqlength)

# read-only text boxes for various keys and outputs


class ReadOnlyText(Text):
    def __init__(self, root):
        Text.__init__(self, root, height=4)
        self.config(state=DISABLED)

    def replace(self, text):
        self.config(state=NORMAL)
        self.delete('1.0', END)
        self.insert('end', text)
        self.config(state=DISABLED)


class EncryptDecryptWindow(Frame):
    #
    # root: tkinter toplevel/root window
    #
    # ----------------------------------------------------------------
    # encrypt: encryption/decryption function
    #  this function will be passed:
    #  - plaintext/ciphertext
    #  - dictionary of keys; textbox labels/values (see below) or defaults
    #  - dictionary of options; group variable, chosen value (see below)
    #
    # ----------------------------------------------------------------
    # keys: array of strings, textboxes will be created and labeled for each
    #  example:
    #  ['n', 'e']
    #
    #  will produce this in UI:
    #    +----------+
    #  n |          |
    #    |          |
    #    +----------+
    #    +----------+
    #  e |          |
    #    |          |
    #    +----------+
    #
    #  and if user inputs 221 and 11, this is what will be passed to encryption function as mentioned above:
    #  {
    #    'n': '221',
    #    'e': '11'
    #  }
    #
    # ----------------------------------------------------------------
    # options: dictionary of dictionaries which will have radio button variables/values as keys and radio button text as values
    #  example:
    #  {
    #    'options1': {
    #      'a': 'single encryption',
    #      'b': 'double encryption'
    #    },
    #    'options2': {
    #      'c': 'something',
    #      'd': 'something else'
    #    }
    #  }
    #
    #  will produce radio buttons like this:
    #  ○ single encryption
    #  ○ double encryption
    #
    #  ○ something
    #  ○ something else
    #
    #  and if the user selects "double encryption" and "something", this is what will be passed to encryption function as mentioned above:
    #  {
    #    'options1': 'b',
    #    'options2': 'c'
    #  }
    #
    # ----------------------------------------------------------------
    # displayDefaults: whether or not to give user option of using pre-existing key(s)
    #
    # ----------------------------------------------------------------
    # defaultKeys: array of default keys to be displayed, must be as long as keys array
    #
    # ----------------------------------------------------------------
    #
    def __init__(self, root, encrypt, keys, options, displayDefaults, defaultKeys, allowSelectFiles, buttonText):
        super().__init__()
        
        if displayDefaults and len(keys) != len(defaultKeys):
            logging.warning(
                'number of keys to be inputted and number of default keys are unequal')
            # default key boxes will just have -
            defaultKeys = [*'-'*len(keys)]

        self.columnconfigure(0, weight = 1)
        self.columnconfigure(1, weight = 3)
        self.columnconfigure(2, weight = 2)

        def chooseFile(targetVariable):
            logging.info('file selection window opened')
            thefilename = filedialog.askopenfilename(initialdir='./', title='Select file...')
            targetVariable.set(thefilename)
            logging.info(f'file chosen: {thefilename}')

        Frame.__init__(self, root)
        keyChoice = StringVar(self, '0')
        if not displayDefaults:
            keyChoice.set('1')

        row_num = 0

        # allow user to select default keys

        if displayDefaults:
            Radiobutton(self, text='Last generated keys',
                        variable=keyChoice, value='0').grid(row=row_num, column=1, pady=10)
            row_num += 1
            for label, key in zip(keys, defaultKeys):
                logging.info(f'creating text box for default key {label}')
                Label(self, text=label).grid(row=row_num, column=0)
                keyBox = ReadOnlyText(self)
                keyBox.replace(key)
                keyBox.grid(row=row_num, column=1, pady=10)
                row_num += 1
            Radiobutton(self, text='Input keys',
                        variable=keyChoice, value='1').grid(row=row_num, column=1, pady=10)
            row_num += 1

        # keys
        
        keyBoxes = {}
        keyFiles = {}
        keyChoices = {}

        for label in keys:
            if allowSelectFiles:
                keyChoices[label] = StringVar(self, 'string')
                keyFiles[label] = StringVar(self, '')
                Radiobutton(self, text='Enter key in text box', variable=keyChoices[label], value='string').grid(row=row_num, column=1)
                Radiobutton(self, text='Read key from file', variable=keyChoices[label], value='file').grid(row=row_num, column=2)
                row_num += 1
                
                def choose_key_file(label):
                    chooseFile(keyFiles[label])
                    logging.info(f'reading from file {keyFiles[label].get()} to key {label}')


                Button(self, text=f'Select file for key {label}...', command=( lambda label=label: choose_key_file(label) ) ).grid(row=row_num, column=2, ipadx=4, ipady=4)

                
            Label(self, text=label).grid(row=row_num, column=0)
            keyBox = Text(self, height=4)
            keyBox.grid(row=row_num, column=1, pady=10)
            keyBoxes[label] = keyBox
            row_num += 1

        # input box

        inputSource = StringVar(self, 'string')
        inputFile = StringVar(self, '')
        if allowSelectFiles:
            Radiobutton(self, text='Enter text in text box', variable=inputSource, value='string').grid(row=row_num, column=1)
            Radiobutton(self, text='Read text from file', variable=inputSource, value='file').grid(row=row_num, column=2)
            row_num += 1
            Button(self, text='Select file...', command=(lambda: chooseFile(inputFile) ) ).grid(row=row_num, column=2, ipadx=4, ipady=4)
                
        Label(self, text='Input').grid(row=row_num, column=0)
        input_text = Text(self, height=4)
        input_text.grid(row=row_num, column=1, pady=20)
        
        
        row_num += 1

        # options
        optionChoices = {}
        optionSubframes = {}
        for (var, choices) in options.items():
            optionChoices[var] = StringVar(self, list(choices.keys())[0])
            optionSubframes[var] = Frame(self)
            optionSubframes[var].grid(row=row_num, column=1)
            for (internal, external) in choices.items():
                Radiobutton(optionSubframes[var], text=external,
                            variable=optionChoices[var], value=internal).pack(side=TOP)
            row_num += 1

        # main button

        def getKeys():
            if keyChoice.get() == '1':
                result = {}
                for key in keys:
                    if allowSelectFiles and keyChoices[key].get() == 'file':
                        file = keyFiles[key]
                        print(f'attempting to open file for key {key}')
                        f = open(file.get())
                        print(f'printing f: {f}')
                        result[key] = f.read().strip()
                        print(result[key])
                        f.close()
                    else:
                        result[key] = keyBoxes[key].get(1.0, END).strip()
            else:
                result = {}
                for (name, key) in zip(keys, defaultKeys):
                    result[name] = key
            print(result)
            return result

        def getOptions():
            result = {}
            for var in options.keys():
                result[var] = optionChoices[var].get()
            return result

        def getInput():
            if inputSource.get() == 'string':
                return input_text.get(1.0, END).strip()
            else:
                f = open(inputFile.get())
                txt = f.read()
                f.close()
                print(txt)
                return txt

        def writeOutput(txt):
            if outputTarget.get() == 'string':
                output_text.replace(txt)
            else:
                f = open(outputFile.get(), 'w')
                f.write(str(txt))
                print(txt)
                f.close()

        Button(self, text=buttonText, command=(lambda: writeOutput(encrypt(
            getInput(), getKeys(), getOptions())))).grid(row=row_num, column=1, ipadx=4, ipady=4, pady=10)
        row_num += 1

        # output box

        outputTarget = StringVar(self, 'string')
        outputFile = StringVar(self, '')
        if allowSelectFiles:
            Radiobutton(self, text='Put text in text box', variable=outputTarget, value='string').grid(row=row_num, column=1)
            Radiobutton(self, text='Write text to file', variable=outputTarget, value='file').grid(row=row_num, column=2)
            row_num += 1
            Button(self, text='Select file...', command=(lambda: chooseFile(outputFile) ) ).grid(row=row_num, column=2, ipadx=4, ipady=4)

        Label(self, text='Output').grid(row=row_num, column=0)
        output_text = ReadOnlyText(self)
        output_text.grid(row=row_num, column=1, pady=20)


rsa_security_levels = {
    '80 bit': 1024,
    '128 bit': 3072,
    # anything longer takes too long when generating primes...
    # '192': 7680,
    # '256': 15360,
}

rsa_params = RSAParameterGenerator()


def open_aes_encrypt(root):
    aes_encrypt_window = Toplevel(root)
    # aesWindow.pack(padx=40, pady=20)

    Button(aes_encrypt_window, text='AES - Encrypt a String Message', command=(lambda: open_aes_string_message_encrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aes_encrypt_window, text='AES - Encrypt a Text File Message', command=(lambda: open_aes_text_file_message_encrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)

    # root.title('CSCI663G VA - Fall 2023')


def open_aes_string_message_encrypt(root):
    aes_string_message_encrypt = Toplevel(root)

    def encrypt(plaintext, keys, options):
        password = keys['Password'].strip()

        return aes.encrypt_string(plaintext, password, [])
    aesFrame = EncryptDecryptWindow(
        aes_string_message_encrypt, encrypt, ['Password'], {}, False, [], False, 'Encrypt')
    aesFrame.pack(padx=20, pady=20)


def open_aes_text_file_message_encrypt(root):
    aes_encrypt_text_file_message_window = Toplevel(root)
    # aesWindow.pack(padx=40, pady=20)

    password_label = tk.Label(
        aes_encrypt_text_file_message_window, text="Password")
    password_label.pack()

    user_password = tk.StringVar()
    password_text_box = tk.Entry(
        aes_encrypt_text_file_message_window, width=100, textvariable=user_password)

    password_text_box.pack()

    # Button(aes_encrypt_text_file_message_window, text='AES - Encrypt String Message', command=(lambda: open_aes_string_message_encrypt(root))
    #        ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aes_encrypt_text_file_message_window, text='AES - Select a Text File to Encrypt', command=(lambda: open_aes_select_text_file_message_encrypt(root, user_password.get()))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)


def open_aes_select_text_file_message_encrypt(root, password):
    # open_aes_text_file_message_encrypt = Toplevel(root)

    selected_file_label = tk.Label(text="Selected File:")
    selected_file_label.pack()

    file_path = filedialog.askopenfilename(title="Select a Text File to Encrypt", filetypes=[
        ("Text files", "*.txt")])
    if file_path:
        selected_file_label.config(text=f"Selected File: {file_path}")
        # process_file(file_path, file_text, selected_file_label)
        # process_file(file_path, selected_file_label)

    # file_to_encrypt_name = os.path.basename(file_path)
    # aes.encrypt(file_to_encrypt_name, "password", "testfile_encrypted.txt")

    file_to_encrypt_name = os.path.basename(file_path)

    # Extract the filename without extension from the full path
    encrypted_file_name, file_to_encrypt_extension = os.path.splitext(
        os.path.basename(file_path))

    encrypted_file_name = list(encrypted_file_name)
    encrypted_file_name.extend("_encrypted.txt")
    print("decrypted_file_name", encrypted_file_name)
    string_encrypted_file_name = "".join(encrypted_file_name)
    print("string_decrypted_file_name", string_encrypted_file_name)
    aes.encrypt(file_to_encrypt_name, password, string_encrypted_file_name)


def open_aes_decrypt(root):
    aesWindow = Toplevel(root)
    # aesWindow.pack(padx=40, pady=20)

    Button(aesWindow, text='AES - Decrypt a String Message', command=(lambda: open_aes_string_message_decrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aesWindow, text='AES - Decrypt a Text File Message', command=(lambda: open_aes_text_file_message_decrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)

    # root.title('CSCI663G VA - Fall 2023')


def open_aes_string_message_decrypt(root):
    aesWindow = Toplevel(root)

    def decrypt(ciphertext, keys, options):
        password = keys['Password'].strip()

        return aes.decrypt_string(ciphertext, password, [])
    aesFrame = EncryptDecryptWindow(
        aesWindow, decrypt, ['Password'], {}, False, [], False, 'Decrypt')
    aesFrame.pack(padx=20, pady=20)


def open_aes_text_file_message_decrypt(root):
    aes_decrypt_text_file_message_window = Toplevel(root)
    # aesWindow.pack(padx=40, pady=20)

    password_label = tk.Label(
        aes_decrypt_text_file_message_window, text="Password")
    password_label.pack()

    user_password = tk.StringVar()
    password_text_box = tk.Entry(
        aes_decrypt_text_file_message_window, width=100, textvariable=user_password)

    password_text_box.pack()

    # Button(aes_encrypt_text_file_message_window, text='AES - Encrypt String Message', command=(lambda: open_aes_string_message_encrypt(root))
    #        ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aes_decrypt_text_file_message_window, text='AES - Select a Text File to Decrypt', command=(lambda: open_aes_select_text_file_message_decrypt(root, user_password.get()))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)


def open_aes_select_text_file_message_decrypt(root, user_password):
    # aesWindow = Toplevel(root)

    selected_file_label = tk.Label(text="Selected File:")
    selected_file_label.pack()

    file_path = filedialog.askopenfilename(title="Select a Text File to Decrypt", filetypes=[
        ("Text files", "*.txt")])
    if file_path:
        selected_file_label.config(text=f"Selected File: {file_path}")
        # process_file(file_path, file_text, selected_file_label)
        # process_file(file_path, selected_file_label)

    file_to_decrypt_name = os.path.basename(file_path)

    # Extract the filename without extension from the full path
    decrypted_file_name, file_to_decrypt_extension = os.path.splitext(
        os.path.basename(file_path))

    decrypted_file_name = list(decrypted_file_name)
    decrypted_file_name.extend("_decrypted.txt")
    print("decrypted_file_name", decrypted_file_name)
    string_decrypted_file_name = "".join(decrypted_file_name)
    print("string_decrypted_file_name", string_decrypted_file_name)
    aes.decrypt(file_to_decrypt_name, "password", string_decrypted_file_name)


def open_rsa_keys(root):
    rsaRoot = Toplevel(root)
    rsaRoot.title('RSA')

    rsaWindow = Frame(rsaRoot)
    rsaWindow.pack(padx=20, pady=20)

    def new_keys(output_box, n_length):
        rsa_params.generate_new_keys(n_length // 2)
        readonly.config(state=NORMAL)
        readonly.delete(1.0, END)
        readonly.insert(
            'end', f'n: {rsa_params.n}\n\nPublic key: {rsa_params.public_key}\n\nPrivate key: {rsa_params.private_key}')
        readonly.config(state=DISABLED)

    security_level = StringVar(rsaWindow)
    security_level.set('80 bit')

    OptionMenu(rsaWindow, security_level, *rsa_security_levels).pack(side=TOP)

    readonly = Text(rsaWindow)
    readonly.delete(1.0, END)
    readonly.insert(
        'end', f'n: {rsa_params.n}\n\nPublic key: {rsa_params.public_key}\n\nPrivate key: {rsa_params.private_key}')
    readonly.pack(side=TOP)
    readonly.config(state=DISABLED)

    Button(rsaWindow, text='Generate new RSA parameters', command=(lambda: new_keys(
        readonly, rsa_security_levels[security_level.get()]))).pack(side=BOTTOM)

    # new_keys(readonly, 1024)


def open_rsa_encrypt(root):
    rsaWindow = Toplevel(root)
    def_n, def_e, _ = rsa_params.get_keys()

    def encrypt(plaintext, keys, options):
        if not (keys['n'].isdigit() and keys['e'].isdigit()):
            return 'keys are not numerical'
        n = int(keys['n'])
        e = int(keys['e'])

        if options['encode'] == '1' and not plaintext.isdigit():
            return 'message is not an integer'

        return rsa.encrypt(plaintext, n, e, options['encode'] == '1')

    rsaFrame = EncryptDecryptWindow(rsaWindow, encrypt, ['n', 'e'], {'encode': {
                                    '0': 'Convert message to bytes and then integer in little-endian order', '1': 'Message is already integer'}}, True, [str(def_n), str(def_e)], False, 'Encrypt')
    rsaFrame.pack(padx=20, pady=20)


def open_rsa_decrypt(root):
    rsaWindow = Toplevel(root)
    def_n, _, def_d = rsa_params.get_keys()

    def decrypt(ciphertext, keys, options):
        if not (keys['n'].isdigit() and keys['d'].isdigit()):
            return 'keys are not numerical'
        n = int(keys['n'])
        d = int(keys['d'])

        if not ciphertext.isdigit():
            return 'ciphertext is not an integer'

        try:
            return rsa.decrypt(int(ciphertext), n, d, options['decode'] == '1')
        except UnicodeDecodeError as e:
            return f'ERROR: {e}\n\nPerhaps you should select the \'Keep message as integer\' option?'

    rsaFrame = EncryptDecryptWindow(rsaWindow, decrypt, ['n', 'd'], {'decode': {
                                    '0': 'Convert decrypted message integer to bytes in little-endian order, then to string', '1': 'Keep message as integer'}}, True, [str(def_n), str(def_d)], True, 'Decrypt')
    rsaFrame.pack(padx=20, pady=20)

root = Tk()

mainWindow = Frame(root)
mainWindow.pack(padx=40, pady=20)

Button(mainWindow, text='AES - Encrypt', command=(lambda: open_aes_encrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='AES - Decrypt', command=(lambda: open_aes_decrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Generate keys',
       command=(lambda: open_rsa_keys(root))).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Encrypt', command=(lambda: open_rsa_encrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Decrypt', command=(lambda: open_rsa_decrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
# Button(mainWindow, text='Test\nRSA - Encrypt', command=( lambda: open_wip_class_window(root) )).pack(fill=X, ipadx=4, ipady=4, pady=4)
root.title('CSCI663G VA - Fall 2023')

root.mainloop()
