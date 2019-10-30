import os, random, struct
import hashlib
import smtplib, ssl
from Crypto.Cipher import AES
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

def main():
    while 1:
        choice = raw_input("Press E to Encrypt a file or D to Decrypt a file or exit to quit: ")
        if choice == "E":
            #Encrypt and Upload
            file = raw_input("Name of file: ")
            aes_password = raw_input("Enter a password to encrypt the file with: ")
            #convert password to 32 byte encryption key
            aes_key = hashlib.sha256(aes_password).digest()
            print ("Encryption Key: "+aes_key.encode('hex_codec'))
            print("Encrypting...")
            #encrypt file and get filename for upload
            encrypted_filename =  encrypt_file(aes_key, file)
            print("Encrypted: "+encrypted_filename)
            #Upload File
            drive_upload(encrypted_filename,aes_password)
        elif choice == "D":
            #Decrypt and Download 
            print("\n\nDownload and Decrypt...")
            drive_download()
            print("Decryption and Download Complete.\n")
        elif choice == "exit":
            break
        else:
            print("Invalid input...")
    print("Program Terminated...")

def authorize():
    gauth = GoogleAuth()
    #load credentials
    gauth.LoadCredentialsFile("credentials.txt")
    if gauth.credentials is None:
        #if credentials aren't saved, load them
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        gauth.Refresh() #refresh
    else:
        gauth.Authorize()
    gauth.SaveCredentialsFile("credentials.txt") # save current creds
    drive = GoogleDrive(gauth)
    return drive

def drive_upload(filename, password, folder_id="1d7hAeZ3oBbzDzE4cOEWlxE5S3UaF3tDb"):
    drive = authorize()
    drive_name = raw_input("What would you like the file to be called in your Google Drive Folder: ")
    save_key(drive_name, password) #store key in keys.txt
    drive_file = drive.CreateFile({'title': drive_name,"parents": [{"kind": "drive#fileLink","id": folder_id}]})
    drive_file.SetContentFile(filename)
    drive_file.Upload() # upload file to drive
    print("Uploaded to Google Drive: "+drive_name)
    email = raw_input("Would you like to send the key in an Email(Type Y or N): ")
    if email == "Y":
        email_key(drive_name, password)
    print("Process Complete\n")

def email_key(filename, key):
    smtp_server = "smtp.gmail.com"
    port = 587 
    sender_email = "drive.encryptor@gmail.com"
    password = "tcomproj2"
    emails = raw_input("Enter the recipient's Email address: ")
    email_list = emails.split()
    #print(email_list)
    message = "\nEncryption Key for file in the following folder: https://drive.google.com/drive/folders/1d7hAeZ3oBbzDzE4cOEWlxE5S3UaF3tDb?usp=sharing\nFile: " + filename + "\nKey: " + key 

    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(smtp_server,port)
        server.ehlo()
        server.starttls() # Secure the connection
        server.login(sender_email, password)
        for user in email_list:
            server.sendmail(sender_email, user, message)

    except Exception as e:
        print(e)
    finally:
        server.quit() 
    
def drive_download():
    drive = authorize()
    file_list = drive.ListFile({'q': "'1d7hAeZ3oBbzDzE4cOEWlxE5S3UaF3tDb' in parents and trashed=false"}).GetList()
    print("Here is the current list of encrypted files in the Google Drive Folder:\n")
    file_id = search_drive() #get file to decrypt
    drive_file = drive.CreateFile({'id': file_id})
    print('Downloading file %s from Google Drive' % drive_file['title']) 
    drive_file.GetContentFile(drive_file['title'])  # Save Drive file as a local file
    #decrypt
    decrypt_password = raw_input("Enter Encryption Password: ")
    decrypt_key = hashlib.sha256(decrypt_password).digest()
    decrypt_file(decrypt_key,drive_file['title'])
    print("File Decrypted. ")

def search_drive():
    drive = authorize()
    file_list = drive.ListFile({'q':"'1d7hAeZ3oBbzDzE4cOEWlxE5S3UaF3tDb' in parents and trashed=false"}).GetList()
    file_arr = []
    index = 1
    for file1 in file_list:
        file2 = drive.CreateFile({'id': file1['id']})
        file2.FetchMetadata()
        file_arr.append(file2)
        print('%i. Title: %s, last modified: %s, created: %s' % (index, file2['title'], file2['modifiedDate'], file2['createdDate']))
        index += 1
    choice = int(input("\nChoose the file to decrypt by entering its index: "))-1
    return file_arr[choice]['id']
    

#AES File Encryption
def encrypt_file(key, input_file, output_file=None, chunksize=64*1024):
    if not output_file:
        output_file = input_file + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16)) # generate initialisation vector
    encryptor = AES.new(key, AES.MODE_CBC, iv) 
    filesize = os.path.getsize(input_file) #get original filesize for decryption 

    with open(input_file, 'rb') as infile:
        with open(output_file, 'w+') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                #ecrypt in chunks
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
    return output_file

def decrypt_file(key, input_file, output_file=None, chunksize=24*1024):
    if not output_file:
        output_file = "download_decrypted"

    with open(input_file, 'rb') as infile:
        f_size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(f_size)

def save_key(filename, key):
    with open("keys.txt",'a') as keyfile:
        keyfile.write("File: " + filename +"\nKey: " + str(key) + "\n\n")
    print("Key saved to keys.txt")


if __name__== "__main__":
    main()