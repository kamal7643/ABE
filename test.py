from ctypes import *


so_file="/Users/kamalswami/Documents/ABE/cpp_cpabe_2/app.so"

app = CDLL(so_file)

def pass_string(str):
    return create_string_buffer(str.encode('utf-8'))


app.setup()
app.enc(pass_string(".ABE_DIR/files/doc.txt"), pass_string(".ABE_DIR/encryption/doc.txt.cpabe"))
app.keygen()
app.dec(pass_string(".ABE_DIR/encryption/doc.txt.cpabe"), pass_string(".ABE_DIR/decryption/doc.txt"))
