#!/usr/sbin/python3

class myError(Exception):
    errorname = 'MY ERROR'
    def __init__(self,msg):
        self.msg = msg
    def __str__(self):
        return f'{self.errorname} : {self.msg}'

class formatError(myError):
    errorname = 'FORMAT ERROR'

class lengthError(myError):
    errorname = 'LENGTH ERROR'

class valueError(myError):
    errorname = 'VALUE ERROR'
