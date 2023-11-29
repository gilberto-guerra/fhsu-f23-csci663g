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
    def __init__(self, root, encrypt, keys, options, displayDefaults, defaultKeys, buttonText):
        if displayDefaults and len(keys) != len(defaultKeys):
            logging.warning(
                'number of keys to be inputted and number of default keys are unequal')
            # default key boxes will just have -
            defaultKeys = [*'-'*len(keys)]

        Frame.__init__(self, root)
        keyChoice = StringVar(self, '0')
        if not displayDefaults:
            keyChoice.set('1')

        # allow user to select

        if displayDefaults:
            defaultsFrame = Frame(self)
            defaultsFrame.pack(side=TOP, pady=20)
            Radiobutton(defaultsFrame, text='Last generated keys',
                        variable=keyChoice, value='0').pack(side=TOP)
            for label, key in zip(keys, defaultKeys):
                defaultKeyFrame = Frame(defaultsFrame)
                defaultKeyFrame.pack(side=TOP, pady=10)
                Label(defaultKeyFrame, text=label).pack(side=LEFT, padx=5)
                keyBox = ReadOnlyText(defaultKeyFrame)
                keyBox.replace(key)
                keyBox.pack(side=RIGHT)
            Radiobutton(defaultsFrame, text='Input keys',
                        variable=keyChoice, value='1').pack(side=TOP)

        # keys

        keyBoxes = []
        keysFrame = Frame(self)
        keysFrame.pack(side=TOP, pady=20)
        for label in keys:
            keyFrame = Frame(keysFrame)
            keyFrame.pack(side=TOP, pady=10)
            Label(keyFrame, text=label).pack(side=LEFT, padx=5)
            keyBox = Text(keyFrame, height=4)
            keyBox.pack(side=RIGHT)
            keyBoxes.append(keyBox)

        # input box

        input_frame = Frame(self)
        input_frame.pack(side=TOP, pady=20)
        Label(input_frame, text='Input').pack(side=LEFT, padx=5)
        input_text = Text(input_frame, height=4)
        input_text.pack(side=RIGHT)

        # options
        optionsFrame = Frame(self)
        optionsFrame.pack(side=TOP, pady=10)
        optionChoices = {}
        optionSubframes = {}
        for (var, choices) in options.items():
            optionChoices[var] = StringVar(self, list(choices.keys())[0])
            optionSubframes[var] = Frame(optionsFrame)
            optionSubframes[var].pack(side=TOP, pady=5)
            for (internal, external) in choices.items():
                Radiobutton(optionSubframes[var], text=external,
                            variable=optionChoices[var], value=internal).pack(side=TOP)

        # main button

        def getKeys():
            if keyChoice.get() == '1':
                return [i.get(1.0, END).strip() for i in keyBoxes]
            else:
                return defaultKeys

        def getOptions():
            result = {}
            for var in options.keys():
                result[var] = optionChoices[var].get()
            return result

        Button(self, text=buttonText, command=(lambda: output_text.replace(encrypt(
            input_text.get(1.0, END).strip(), getKeys(), getOptions())))).pack(side=TOP, pady=10)

        # output box

        output_frame = Frame(self)
        output_frame.pack(side=TOP, pady=20)
        Label(output_frame, text='Output').pack(side=LEFT, padx=5)
        output_text = ReadOnlyText(output_frame)
        output_text.pack(side=RIGHT)


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

    Button(aes_encrypt_window, text='AES - Encrypt String Message', command=(lambda: open_aes_string_message_encrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aes_encrypt_window, text='AES - Encrypt Text File Message', command=(lambda: open_aes_text_file_message_encrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)

    # root.title('CSCI663G VA - Fall 2023')


def open_aes_string_message_encrypt(root):
    aes_string_message_encrypt = Toplevel(root)

    def encrypt(plaintext, keys, options):
        password = keys[0].strip()

        return aes.encrypt_string(plaintext, password, [])
    aesFrame = EncryptDecryptWindow(
        aes_string_message_encrypt, encrypt, ['Password'], {}, False, [], 'Encrypt')
    aesFrame.pack(padx=20, pady=20)


def open_aes_text_file_message_encrypt(root):
    # aesWindow = Toplevel(root)

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
    aes.encrypt(file_to_encrypt_name, "password", string_encrypted_file_name)


def open_aes_decrypt(root):
    aesWindow = Toplevel(root)
    # aesWindow.pack(padx=40, pady=20)

    Button(aesWindow, text='AES - Decrypt String Message', command=(lambda: open_aes_string_message_decrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)
    Button(aesWindow, text='AES - Decrypt Text File Message', command=(lambda: open_aes_text_file_message_decrypt(root))
           ).pack(fill=X, ipadx=4, ipady=4, pady=4)

    # root.title('CSCI663G VA - Fall 2023')


def open_aes_string_message_decrypt(root):
    aesWindow = Toplevel(root)

    def decrypt(ciphertext, keys, options):
        password = keys[0].strip()

        return aes.decrypt_string(ciphertext, password, [])
    aesFrame = EncryptDecryptWindow(
        aesWindow, decrypt, ['Password'], {}, False, [], 'Decrypt')
    aesFrame.pack(padx=20, pady=20)


def open_aes_text_file_message_decrypt(root):
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
        if not (keys[0].isdigit() and keys[1].isdigit()):
            return 'keys are not numerical'
        n = int(keys[0])
        e = int(keys[1])

        if options['encode'] == '1' and not plaintext.isdigit():
            return 'message is not an integer'

        return rsa.encrypt(plaintext, n, e, options['encode'] == '1')

    rsaFrame = EncryptDecryptWindow(rsaWindow, encrypt, ['n', 'e'], {'encode': {
                                    '0': 'Convert message to bytes and then integer in little-endian order', '1': 'Message is already integer'}}, True, [str(def_n), str(def_e)], 'Encrypt')
    rsaFrame.pack(padx=20, pady=20)


def open_rsa_decrypt(root):
    rsaWindow = Toplevel(root)
    def_n, _, def_d = rsa_params.get_keys()

    def decrypt(ciphertext, keys, options):
        if not (keys[0].isdigit() and keys[1].isdigit()):
            return 'keys are not numerical'
        n = int(keys[0])
        d = int(keys[1])

        if not plaintext.isdigit():
            return 'ciphertext is not an integer'

        try:
            return rsa.decrypt(int(ciphertext), n, d, options['decode'] == '1')
        except UnicodeDecodeError as e:
            return f'ERROR: {e}\n\nPerhaps you should select the \'Keep message as integer\' option?'

    rsaFrame = EncryptDecryptWindow(rsaWindow, decrypt, ['n', 'd'], {'decode': {
                                    '0': 'Convert decrypted message integer to bytes in little-endian order, then to string', '1': 'Keep message as integer'}}, True, [str(def_n), str(def_d)], 'Decrypt')
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
