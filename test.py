from ctypes import *
import time

so_file="/Users/kamalswami/Documents/ABE/cpp_cpabe_2/app.so"

app = CDLL(so_file)

def pass_string(str):
    return create_string_buffer(str.encode('utf-8'))

import time

# app.keygen()

t1 = time.time()
app.dec(pass_string(".ABE_DIR/encryption/output.dat.cpabe"), pass_string(".ABE_DIR/decryption/output.dat"))
print(time.time()-t1)
t1=time.time()

app.dec(pass_string(".ABE_DIR/encryption/output1.dat.cpabe"), pass_string(".ABE_DIR/decryption/output1.dat"))
print(time.time()-t1)
t1=time.time()

app.dec(pass_string(".ABE_DIR/encryption/output2.dat.cpabe"), pass_string(".ABE_DIR/decryption/output2.dat"))
print(time.time()-t1)
t1=time.time()

app.dec(pass_string(".ABE_DIR/encryption/output3.dat.cpabe"), pass_string(".ABE_DIR/decryption/output3.dat"))
print(time.time()-t1)
t1=time.time()

app.dec(pass_string(".ABE_DIR/encryption/output4.dat.cpabe"), pass_string(".ABE_DIR/decryption/output4.dat"))
print(time.time()-t1)
t1=time.time()

app.dec(pass_string(".ABE_DIR/encryption/output5.dat.cpabe"), pass_string(".ABE_DIR/decryption/output5.dat"))
print(time.time()-t1)
t1=time.time()

# app.setup()
# app.enc(pass_string(".ABE_DIR/files/doc.txt"), pass_string(".ABE_DIR/encryption/doc.txt.cpabe"))
# app.keygen()
# app.dec(pass_string(".ABE_DIR/encryption/doc.txt.cpabe"), pass_string(".ABE_DIR/decryption/doc.txt"))
