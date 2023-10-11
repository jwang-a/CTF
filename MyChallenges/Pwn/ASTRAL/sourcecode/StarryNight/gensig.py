from pwn import *
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from assembler import aasm
import sys

###Util
def genKey(size):
    '''
    k = RSA.generate(size)
    print(f'n = {k.n}')
    print(f'e = {k.e}')
    print(f'd = {k.d}')
    print(f'p = {k.p}')
    print(f'q = {k.q}')
    '''
    #n, e, d, p, q
    n = 21171009082903914951667318370642291045692796869958954643722088216142147882253767840887961100355137710362089495842852802587997892237625941064021250560476799326167191827697121941664794224698136464211627744698488458728738531470357408114552250412380210131627601562747041931086880317900979156590999732467529644272118410952441808977318917199874844809309666527342405701370009997253257393475623148604320310819277246488115240652534663038253877478550757625917385995616022874955900085296787079261560024157208651754992639295414413303051790549870265343065330370613104200620617655392887957154686849585510179728449780413388407485437
    e = 65537
    d = 1610107298494954576771103828201990313021565265408744978912245268951988961687647319238686850396647620929738080315771840049120779016210493259507574623587538139393759645195834109552508516020746855543384738186267926521182157033143551145077697394111815651442160506112912457772247481949096775275625836039966501815186091296962456250361999034430216192307282026608357073654805784882869176163072093716668340111897748037285113505033467615759514537063051266117269168609094815157533508013585686085106853147229077530260563057006340468064491249346259710638459872691616543300897343211945547136911447593155569475182437025095589705153
    p = 134044562026558397395438271043288356414291825175675883159490011085282417582339680523519465390585341987506003474384039595224765284764033208095162251323944101019624805110895671722701334251805913017367906573654002903179372603553250865107088458905591402201596665174871103887468507363529267586248647333373151288897
    q = 157940081737215714101272835747726670030883118110573418327888351745825766243034021141082130293326962308794122812021643730127210359909773858053458232302462101221368621273042912989097374820896132106599699654192664950598693111405879872729221562288749012832240796190575347983220641281491057761896899682073808133821
    k = RSA.construct((n, e, d, p, q))
    s = pkcs1_15.new(k)
    return s

def compileApplet(fname, signer):
    with open(fname, 'r') as f:
        data = f.read()
    bcode = aasm(data)
    signature = signer.sign(SHA256.new(bcode))
    return bcode, signature

signer = genKey(2048)

bcode, authsig = compileApplet(sys.argv[1], signer)
print(binascii.hexlify(bcode))
print(binascii.hexlify(authsig))
