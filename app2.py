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
# my_functions.keygen()
# my_functions.enc(pass_string(".ABE_DIR/files/test.txt"), pass_string(".ABE_DIR/encryption/test.txt.cpabe"))
# my_functions.dec(pass_string(".ABE_DIR/encryption/test.txt.cpabe"), pass_string(".ABE_DIR/decryption/test.txt"))

# my_functions.reciver(pass_string("working better!"))


# This is how to send string to c function
# string1 = "my string 1"
# b_string1 = string1.encode('utf-8')
# my_functions.reciver(create_string_buffer(b_string1))

result = {
    'name':'Kamal swami',
    'dep': 'cs'
}

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method=='GET':
        return render_template('landing.html')
        pass
    else:
        pass

@app.route('/encrypt', methods=['GET'])
def encrypt():
    return render_template('encrypt.html', result=result)

@app.route('/encrypt', methods = ['POST'])  
def success():  
    if request.method == 'POST':  
        os.mkdir(".ABE_DIR/files")
        os.mkdir(".ABE_DIR/encryption")
        f = request.files['policies']
        f.save(".ABE_DIR/rules.txt")  
        files = request.files.getlist("files")
  
        # Iterate for each file in the files List, and Save them
        for file in files:
            file.save(".ABE_DIR/files/"+file.filename)
            my_functions.enc(pass_string(".ABE_DIR/files/"+file.filename),pass_string(".ABE_DIR/encryption/"+file.filename+".cpabe"))
        
        # os.mkdir(".ABE_DIR/encrypted")
        # ABE.enc()
        
        return redirect("/encryption/download")
    
@app.route("/encryption/download", methods=['GET', 'POST'])
def down_enc():
    if request.method=='GET':
        return render_template('infoencryption.html')
        pass
    elif request.method=='POST':
        archived = shutil.make_archive('encyption', 'zip', '.ABE_DIR/encryption')
        
        shutil.rmtree(".ABE_DIR/files");
        shutil.rmtree(".ABE_DIR/encryption")
        return send_file('encyption.zip')
        pass

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method=='GET':
        return render_template('decrypt.html')
    elif request.method=='POST':
        os.mkdir(".ABE_DIR/encryption")
        os.mkdir(".ABE_DIR/decryption")
        f = request.files['attribute']
        f.save(".ABE_DIR/attribute.txt")  
        files = request.files.getlist("files")
        my_functions.keygen()
        # Iterate for each file in the files List, and Save them
        for file in files:
            file.save(".ABE_DIR/encryption/"+file.filename)

        for file in files:
            my_functions.dec(pass_string(".ABE_DIR/encryption/"+file.filename), pass_string((".ABE_DIR/decryption/"+file.filename).replace(".cpabe", "")))
        # ABE.keygen()
        # ABE.dec()
        return redirect("/decryption/download")

@app.route("/decryption/download", methods=['GET', 'POST'])
def down_dec():
    if request.method=='GET':
        return render_template('infodecryption.html')
        pass
    elif request.method=='POST':
        archived = shutil.make_archive('decryption', 'zip', '.ABE_DIR/decryption')
        shutil.rmtree(".ABE_DIR/decryption")
        shutil.rmtree(".ABE_DIR/encryption")
        return send_file('decryption.zip')
        pass


app.run(host='0.0.0.0', port=5000, debug=True)