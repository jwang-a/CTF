#!/usr/sbin/python3

from myErrors import *

class User(object):
    def __init__(self,name,isvip,isadmin,desc):
        self.name = name
        self.isvip = isvip
        self.isadmin = isadmin
        self.desc = desc

    @classmethod
    def construct(cls,name,isvip,isadmin,desc):
        if len(name)>=0x20:
            raise lengthError('Username length not in acceptable range')
        if isvip not in (0,1):
            raise valueError('Invalid VIP status code')
        if isadmin not in (0,1):
            raise valueError('Invalid ADMIN status code')
        if len(desc)>=0x20:
            raise lengthError('Description length not in acceptable range')
        return cls(name,isvip,isadmin,desc)

    @classmethod
    def deserialize(cls,token):
        token = token.split('||')
        if len(token)!=4:
            raise formatError('Invalid token fields count')
        if token[0][:5]!='name:':
            raise formatError('Name field not found')
        elif len(token[0][5:])>=0x20:
            raise formatError('Username length not in acceptable range')
        if token[1][:6]!='isvip:':
            raise formatError('VIP status field not found')
        elif len(token[1][6:])!=1:
            raise formatError('Corrupted VIP status field')
        if token[2][:8]!='isadmin:':
            raise formatError('ADMIN status field not found')
        elif len(token[2][8:])!=1:
            raise formatError('Corrupted ADMIN status field')
        if token[3][:5]!='desc:':
            raise formatError('Description field not found')
        elif len(token[3][5:])>=0x20:
            raise formatError('Description length not in acceptable range')
        return cls(token[0][5:],int(token[1][6:]),int(token[2][8:]),token[3][5:])

    def serialize(self):
        return f'name:{self.name}||isvip:{self.isvip}||isadmin:{self.isadmin}||desc:{self.desc}'

    def print_user(self):
        print(f"{' user info ':*^50}")
        print(f"*{' '*48}*")
        print(f'* username    : {self.name: <32} *')
        print(f'* description : {self.desc: <32} *')
        print(f'* isvip       : {self.isvip==1: <32} *')
        print(f'* isadmin     : {self.isadmin==1: <32} *')
        print(f"*{' '*48}*")
        print(f"{'*'*50}")
