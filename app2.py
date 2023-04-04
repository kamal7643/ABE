from ctypes import *
from flask import Flask, render_template, request, redirect, send_file
from distutils.log import debug
from fileinput import filename
import shutil 
import os

so_file = "/Users/kamalswami/Documents/ABE/cpp_cpabe_2/app.so"

my_functions = CDLL(so_file)


app = Flask(__name__)

def pass_string(str):
    return create_string_buffer(str.encode('utf-8'))

my_functions.setup()
my_functions.keygen()
my_functions.enc(pass_string(".ABE_DIR/files/test.txt"), pass_string(".ABE_DIR/encryption/test.txt.cpabe"))
my_functions.dec(pass_string(".ABE_DIR/encryption/test.txt.cpabe"), pass_string(".ABE_DIR/decryption/test.txt"))

my_functions.reciver(pass_string("working better!"))


# This is how to send string to c function
# string1 = "my string 1"
# b_string1 = string1.encode('utf-8')
# my_functions.reciver(create_string_buffer(b_string1))


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method=='GET':
        return render_template('landing.html')
        pass
    else:
        pass

