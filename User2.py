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

#to connect s3
s3 = boto3.resource(
    service_name='s3',
    region_name='us-east-2',
    aws_access_key_id='AKIA4GSXQZJHKMYOCGPC',
    aws_secret_access_key='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'
)

@app.route('/')
@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/encryption')
def encryption():
    return render_template('encryption.html')

@app.route('/decrypt')
def decryption():
    bucket = s3.Bucket('dhke')
    files = []
    for obj in bucket.objects.all():
        files.append(obj.key)
    return render_template('decryption.html', files=files)


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



@app.route('/generate_key', methods=['POST','GET'])
def generate_key():

    # create a socket object
    s = socket.socket()

    # connect to the server
    s.connect(("localhost", 4001))

    #generate two prime no. n and q
    n2 = gen_prime(2000, 5000)
    print('n = ',n2)
    q2 = gen_prime(500, 1000)
    print('q = ',q2)
    m2 = gen_prime(100, 200) #base for log
    print('m = ',m2)

    y = int(request.form['y']) #secret key
    print('y=',y)

    s1 = int(request.form['s1'])
    print('s = ',s1)

    # Accept a connection from User 1 and receive public key A
    
    data = s.recv(4001)
    A = int(data.decode()) 
    print('A = ',A)

    #user 2

    B = public_key(y, n2, q2) #public key
    print('B=',B)

    # Send public key B to User 1
    s.sendall(str(B).encode())


    #shared key
    k2 = public_key(y, A, q2)
    print('k2 = ',k2)

    #extended part

    # Receive public key G from User 2
    data = s.recv(4001)
    G = int(data.decode())
    print('G = ',G)

    #user 2
    
    D = logarithmic(m2, s1, k2)
    print('D = ',D)
    H = D*s1
    H = int(float(H))
    print('H = ',H)

    # Send public key H to User 2
    s.sendall(str(H).encode())


    #final key shared
    FK2 = H*G
    print('FK2 = ',FK2)

    s.close()

    #print('Final key of user 1 = ',FK1)
    return render_template('index2.html', final_keys2 = FK2)



#file encryption

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



#file decryption

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
    

if __name__ == "__main__":
    app.run(debug=True, port=2001,host= '0.0.0.0')
    