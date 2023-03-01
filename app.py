from flask import Flask, render_template, request, redirect, send_file
from distutils.log import debug
from fileinput import filename
from py4j.java_gateway import JavaGateway
import shutil 
import os


app = Flask(__name__)
gateway = JavaGateway()
ABE = gateway.entry_point




ABE.setup()

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
        os.mkdir(".dir/.files")
        f = request.files['policies']
        f.save(".dir/policies.json")  
        files = request.files.getlist("files")
  
        # Iterate for each file in the files List, and Save them
        for file in files:
            file.save(".dir/.files/"+file.filename)
        
        os.mkdir(".dir/encrypted")
        ABE.enc()
        
        return redirect("/encryption/download")
        # return render_template("Acknowledgement.html", name = f.filename)  


@app.route("/encryption/download", methods=['GET', 'POST'])
def down_enc():
    if request.method=='GET':
        return render_template('infoencryption.html')
        pass
    elif request.method=='POST':
        archived = shutil.make_archive('encyption', 'zip', '.dir/encrypted')
        
        shutil.rmtree(".dir/.files");
        shutil.rmtree(".dir/encrypted")
        return send_file('encyption.zip')
        pass


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method=='GET':
        return render_template('decrypt.html')
    elif request.method=='POST':
        os.mkdir(".dir/encrypted")
        os.mkdir(".dir/decrypted")
        f = request.files['attribute']
        f.save(".dir/attribute.json")  
        files = request.files.getlist("files")
  
        # Iterate for each file in the files List, and Save them
        for file in files:
            file.save(".dir/encrypted/"+file.filename)
        ABE.keygen()
        ABE.dec()
        return redirect("/decryption/download")

@app.route("/decryption/download", methods=['GET', 'POST'])
def down_dec():
    if request.method=='GET':
        return render_template('infodecryption.html')
        pass
    elif request.method=='POST':
        archived = shutil.make_archive('decryption', 'zip', '.dir/decrypted')
        shutil.rmtree(".dir/decrypted")
        shutil.rmtree(".dir/encrypted")
        return send_file('decryption.zip')
        pass

app.run(host='0.0.0.0', port=5000, debug=True)


