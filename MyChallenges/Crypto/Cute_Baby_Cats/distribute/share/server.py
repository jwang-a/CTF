#!/usr/sbin/python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
from userClass import User
from myErrors import *
import secret

def myinput(prompt):
    '''
    python input prompts to stderr by default, and there is no option to change this afaik
    this wrapper is just normal input with stdout prompt
    '''
    print(prompt,end='')
    return input()

def encrypt(m):
    aes = AES.new(secret.key,AES.MODE_CBC,secret.iv)
    return binascii.hexlify(secret.iv+aes.encrypt(pad(m.encode(),0x10))).decode()

def decrypt(c):
    aes = AES.new(secret.key,AES.MODE_CBC,secret.iv)
    return unpad(aes.decrypt(binascii.unhexlify(c)[0x10:]),0x10).decode()

def get_token():
    token = secret.user.serialize()
    return encrypt(token)

def create_user():
    try:
        username =myinput('Username : ')
        description = myinput('Description : ')
        if len(username)>=0x10:
            raise lengthError('Username length not in acceptable range')
        if len(description)>=0x10:
            raise lengthError('Description length not in acceptable range')
        newUser = secret.User.construct(username,0,0,description)
        token = newUser.serialize()
        return encrypt(token)
    except Exception as e:
        if e.__class__.__name__=='UnicodeDecodeError':
            print('Unicode Decode Error')
        else:
            print(e)
        return None

def login(ctoken):
    global LOGIN,USER
    try:
        token = decrypt(ctoken)
        USER = User.deserialize(token)
        LOGIN = True
    except Exception as e:
        if e.__class__.__name__=='UnicodeDecodeError':
            print('Unicode Decode Error')
        else:
            print(e)
        USER = None
        LOGIN = False
		

def logout():
    global LOGIN,USER
    USER = None
    LOGIN = False

def menu():
    print(f"{' menu ':=^20}")
    if LOGIN is False:
        print('1. get token')
        print('2. login')
        print('3. give up')
    else:
        print('1. account info')
        print('2. create user')
        print('3. get secret')
        print('4. logout')
    print(f"{'':=^20}")

if __name__=='__main__':
    LOGIN = False
    USER = None
    while True:
        menu()
        choice = myinput('your choice : ').strip()
        try:
            choice=int(choice)
        except:
            print('Invalid Command')
            continue
        if LOGIN is False:
            if choice==1:
                print(f'Here is your token : {get_token()}')
            elif choice==2:
                ctoken = myinput('Please provide your login token (hex encoded) : ').strip()
                login(ctoken)
            elif choice==3:
                print('Goodbye')
                break
            else:
                print('Invalid Command')
        else:
            if choice==1:
                if USER.isvip==1 or USER.isadmin==1:
                    USER.print_user()
                else:
                    print('Privilege not granted')
            elif choice==2:
                if USER.isvip==1 and USER.isadmin==1:
                    token = create_user()
                    if token is not None:
                        print(f'Here is your token : {token}')
                else:
                    print('Privilege not granted')
            elif choice==3:
                if USER.isvip==1 and USER.isadmin==1 and USER.name=='king of the cats':
                    print(f'Congratulations, here is your flag : {secret.flag}')
                else:
                    print('Access Denied')
            elif choice==4:
                logout()
            else:
                print('Invalid Command')
