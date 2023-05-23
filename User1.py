from flask import Flask, render_template, request
from jinja2 import FileSystemLoader
from random import randint
import math
import socket
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import boto3
import os

app = Flask(__name__)

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/encryption')
def encryption():
    return render_template('encryption.html')

@app.route('/decryption')
def decryption():
    bucket = s3.Bucket('dhke')
    files = []
    for obj in bucket.objects.all():
        files.append(obj.key)
    return render_template('decryption.html', files=files)


s3 = boto3.resource(
    service_name = 's3',
    region_name = 'us-east-2',
    aws_access_key_id = 'AKIA4GSXQZJHKMYOCGPC',
    aws_secret_access_key = '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'
)


@app.route('/generate_key', methods=['POST','GET'])
def generate_key():

    s = socket.socket()
    # bind the socket to a public host and a well-known port
    s.bind(("localhost", 4001))

    # listen for incoming connections
    s.listen(1)

    # wait for a connection
    conn, addr = s.accept()
    print('Connected by', addr)

    #generate two prime no. n and q
    n = gen_prime(2000, 5000)
    print('n = ',n)
    q = gen_prime(500, 1000)
    print('q = ',q)
    m = gen_prime(100, 200) #base for log
    print('m = ',m)

    x = int(request.form['x']) #secret key
    print('x=',x)

    t = int(request.form['t'])
    print('t = ',t)
    
    A = public_key( x, n , q) #public key
    print('A=',A)
    

    # Send public key A to User 2
    conn.sendall(str(A).encode())


    # Receive public key B from User 2
    data = conn.recv(4001)
    B = int(data.decode())
    print("B = "+str(B))
    #shared key
    k1 = public_key(x, B, q)
    print('k1 = ', k1)

    #extended part
    
    C = logarithmic(m, t, k1)
    print('c = ',C)
    G = C*t
    G = int(float(G))
    print('G = ',G)

   
    # Send public key G to User 2
    conn.sendall(str(G).encode())

    # Receive public key B from User 2
    data = conn.recv(4001)
    H = int(data.decode())
    print('H = ',H)

    #final key shared
    FK1 = G*H
    print('FK1 = ',FK1)

    conn.close()

    return render_template('index.html', final_keys = FK1)



#for encryption

@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Get file and key from form data
    file = request.files['file']
    key = request.form['key']

    # Convert key to bytes and pad to AES block size
    key = key.encode('UTF-8')
    key = pad(key, AES.block_size)

    # Read file data and encrypt using AES in CFB mode
    data = file.read()
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('UTF-8')
    ciphertext = b64encode(ciphertext).decode('UTF-8')
    to_write = iv + ciphertext

    # Upload encrypted file to S3 bucket
    s3_bucket_name = 'dhke'
    s3_file_key = 'enc_' + file.filename
    s3.Bucket(s3_bucket_name).put_object(Key=s3_file_key, Body=to_write.encode())

    return render_template('encryption.html', output=f'File encrypted and saved to S3 as {s3_file_key}')



#for decryption

@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Get file and key from form data
    file = request.form['file']
    key = request.form['key']

    # Convert key to bytes and pad to AES block size
    key = key.encode('UTF-8')
    key = pad(key, AES.block_size)

    # Download encrypted file from S3
    s3.Bucket('dhke').download_file(Key=file, Filename=file)

    # Read encrypted file data and decrypt using AES in CFB mode
    with open(file, 'r') as f:
        try:
            data = f.read()
            length = len(data)
            iv = data[:24]
            iv = b64decode(iv)
            ciphertext = data[24:length]
            ciphertext = b64decode(ciphertext)
            cipher = AES.new(key, AES.MODE_CFB, iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted, AES.block_size)

            # Save decrypted file to disk
            with open('dec_' + file, 'wb') as f:
                f.write(decrypted)

        except(ValueError,KeyError):
            return render_template('decryption.html', output2=f'Wrong encryption key!!!')

    return render_template('decryption.html', output2=f'File decrypted and saved as dec_' + file)



#to generate prime number
def gen_prime(start, stop):
    prime_list = []

    #to generate list of prime no.
    for n in range(start, stop):
        if n > 1:
            for i in range (2, n):
                if (n % i) == 0:
                    break
                else :
                    prime_list.append(n)
    
    #to randomly pick a no. as prime no. from prime_list
    x = randint(1, len(prime_list))
    return prime_list[x]

#to generate public key
def public_key(x, y, z):
    r = (y**x)%z
    return r

#logarithmic function
def logarithmic(a, b, c):
    r = math.log(c, a)
    z = b*r
    return z



    

if __name__ == "__main__":
    app.run(debug=True, port=2000,host= '0.0.0.0')

    