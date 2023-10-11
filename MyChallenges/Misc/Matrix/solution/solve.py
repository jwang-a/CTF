'''
credits : s123unny, who helped extend / implement my idea
'''

import math
import copy

import numpy as np
import random

from pwn import *

### setting ###
precision = 1e-8
KERNEL_SIZE = (5,5)
INPUT_SIZE = (7,7)
HORIZONTAL_WIDTH = INPUT_SIZE[0]-(KERNEL_SIZE[0]-1)
VERTIVAL_WIDTH = INPUT_SIZE[1]-(KERNEL_SIZE[1]-1)
LINEAR_SIZE = HORIZONTAL_WIDTH*VERTIVAL_WIDTH

np.set_printoptions(formatter={'float': '{:.6f}'.format})

Qcnt = 0

def oracle(program,data):
    global Qcnt
    if Qcnt % 100 == 0:
        print(Qcnt)
    Qcnt += 1
    program.sendline(','.join(str(x) for x in data.reshape(-1)).encode())
    return int(program.recvline())


def debug():
    # print('C_Bias :', C_Bias)
    # print('Csign :',Csign)
    # print('Wsign :',Wsign)

    # print('C\' :\n',np.array(Cval))
    # print('W\' :\n',np.array(Wval))

    print(f'QueryCnt: {Qcnt}')


def binsearch(program,precision,lbnd,ubnd,mode='above',debug=False):
    lres = oracle(program,lbnd)
    ures = oracle(program,ubnd)
    while np.linalg.norm(ubnd-lbnd)>precision*0.5:
        interpolation = ubnd/2+lbnd/2
        if np.all(interpolation==ubnd) or np.all(interpolation==lbnd):
            raise Exception("binsearch failed")
            #this means we are stuck, perturb diff a bit
            #solving this requires more precise math(ex.gmpy2), we temporarily ignore it now
            if mode=='above':
                return ubnd
            elif mode=='under':
                return lbnd

        res = oracle(program,interpolation)
        if res==lres:
            lbnd = interpolation
        else:
            ubnd = interpolation
    if mode=='above':
        return ubnd
    elif mode=='under':
        return lbnd

def solve():
    global Qcnt
    Qcnt = 0

    program = remote('44.200.251.163', 10101)
    program.recvuntil(b'secret digest : ')
    flagdigest = program.recvline().decode()[:-1]
    try:
        ##### try to solve #####
        Csign = [[0 for i in range(KERNEL_SIZE[0])] for j in range(KERNEL_SIZE[1])]
        Wsign = [0 for i in range(LINEAR_SIZE)]
        Cval = [[0 for i in range(KERNEL_SIZE[0])] for j in range(KERNEL_SIZE[1])]
        Wval = [0 for i in range(LINEAR_SIZE)]
        CvalFound = [[False for i in range(KERNEL_SIZE[0])] for j in range(KERNEL_SIZE[1])]
        WvalFound = [False for i in range(LINEAR_SIZE)]
        ###assume C_Bias = +-1, holds for any C_Bias!=0 under scaling
        C_Bias = 0

        # all zeros:
        # C_Bias =  1 -> B_f + sigma w_i 
        # C_Bias = -1 -> B_f
        Z = np.zeros(INPUT_SIZE)
        ztag = oracle(program,Z)

        # (input.shape[0], input.shape[1], kernel.shape[0], kernel.shape[1], w)
        corners = ((0,0,0,0,0),
                   (0,INPUT_SIZE[1]-1,0,KERNEL_SIZE[0]-1,2),
                   (INPUT_SIZE[1]-1,0,KERNEL_SIZE[1]-1,0,6),
                   (INPUT_SIZE[0]-1,INPUT_SIZE[1]-1,KERNEL_SIZE[1]-1,KERNEL_SIZE[0]-1,8))

        # given only value at the corner, result is different or not
        # C_Bias = <+> -> B_f + max(i * c_i + <+>, 0) * w_i + <+> * sigma w_j (j != i)
        # C_Bias = <-> -> B_f + max(i * c_i + <->, 0) * w_i
        diff_sign = []
        same_sign = []
        for point in corners:
            I = copy.deepcopy(Z)
            I[point[0],point[1]] = 1./pow(precision,2)
            res1 = oracle(program,I)
            res2 = oracle(program,-I)

            Windex = point[4]
            if res1==ztag and res2==ztag:
                Wsign[Windex] = (ztag)*2-1
            else:
                Wsign[Windex] = (1-ztag)*2-1
            if res1!=ztag:
                diff_sign.append(point)
                Csign[point[2]][point[3]] = 1
            elif res2!=ztag:
                diff_sign.append(point)
                Csign[point[2]][point[3]] = -1
            else:
                same_sign.append(point)


        if len(diff_sign) < 2:
            print("try again")
            return

        thres_diff = []
        for point in diff_sign:
            I = copy.deepcopy(Z)
            I[point[0],point[1]] = Csign[point[2]][point[3]]/pow(precision,2)
            res = binsearch(program,precision,Z,I)
            thres_diff.append((point,float(res[point[0],point[1]])))
            if len(thres_diff)>=2:   #we only need first entry as pivot if there are same signed ones
                break

        BASE = copy.deepcopy(Z)
        BASE[thres_diff[0][0][0],thres_diff[0][0][1]] = thres_diff[0][1]
        I = copy.deepcopy(BASE)
        I[thres_diff[1][0][0],thres_diff[1][0][1]] = -Csign[thres_diff[1][0][2]][thres_diff[1][0][3]]/pow(precision,2)
        # first diff as i, and second as j
        # C_Bias = <+> -> B_f + max(i * c_i + <+>, 0) * w_i + <+> * sigma w_k (k != i && k != j)
        # C_Bias = <-> -> B_f + max(i * c_i + <->, 0) * w_i
        if oracle(program,I)==ztag:
            C_Bias = 1
        else:
            C_Bias = -1


        def constructSign(BASE, point, Csign):
            I1 = copy.deepcopy(BASE)
            I2 = copy.deepcopy(BASE)
            I1[point[0],point[1]] = 1./pow(precision,2)
            I2[point[0],point[1]] = -1./pow(precision,2)
            if oracle(program,I1)==ztag:
                Csign[point[2]][point[3]] = 1
                return I1
            elif oracle(program,I2)==ztag:
                Csign[point[2]][point[3]] = -1
                return I2
            else:
                raise Exception('construct sign error')

        ##### construct corner #####
        # set a basis to measure W
        Wbasis = diff_sign[0]
        WbasisIndex = Wbasis[4]
        Wval[WbasisIndex] = Wsign[WbasisIndex]
        WvalFound[WbasisIndex] = True

        if C_Bias == 1:
            thres_diff_margin = []
            CW_ratio = []
            for idx,point in enumerate(diff_sign):
                BASE = copy.deepcopy(Z)
                # base = B_f + B2 * sigma W_all
                # point = j
                # B_f + (y * Cj + B2) * Wj + B2 * sigma Wk (k != i && k != j) = base - B2Wi + yCjWj
                BASE[point[0],point[1]] = -Csign[point[2]][point[3]]/pow(precision,2)
                I = copy.deepcopy(BASE)
                if idx!=0:
                    I[Wbasis[0],Wbasis[1]] = Csign[Wbasis[2]][Wbasis[3]]/pow(precision,2)
                else:
                    I[thres_diff[1][0][0],thres_diff[1][0][1]] = Csign[thres_diff[1][0][2]][thres_diff[1][0][3]]/pow(precision,2)
                BASE2 = binsearch(program,precision,BASE,I,mode='under')
                if idx!=0:
                    CW_ratio.append((point,BASE2[Wbasis[0],Wbasis[1]]))
                I = copy.deepcopy(BASE2)
                I[point[0],point[1]] = 0
                # B_f + (x * Cj + B2) * Wj + B2 * sigma Wk (k != j) = base + xCjWj
                res = binsearch(program,precision,BASE2,I)
                thres_diff_margin.append((point,res[point[0],point[1]]))
            for point in thres_diff_margin:
                '''
                B2+xCj = 0
                Cj = -B2/x (B2=1)
                '''
                Cval[point[0][2]][point[0][3]] = float(-C_Bias/point[1])
                CvalFound[point[0][2]][point[0][3]] = True
            for point in CW_ratio:
                '''
                base + xCjWj = 0
                base - B2Wi + yCjWj = 0
                B2Wi+(x-y)CjWj = 0
                Wi = (y-x)CjWj/B2  (Wj=0, B2=1)
                '''
                Wval[point[0][4]] = float((point[1]-thres_diff[0][1])*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex])
                WvalFound[point[0][4]] = True
            # Zval = base = -xCjWj
            Zval = float(-thres_diff[0][1]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex])
            
            if len(same_sign)!=0:
                if len(same_sign)==1:
                    BASE = copy.deepcopy(Z)
                    BASE[thres_diff[0][0][0],thres_diff[0][0][1]] = thres_diff[0][1]+Csign[thres_diff[0][0][2]][thres_diff[0][0][3]]
                    constructSign(BASE, same_sign[0], Csign)
          
                    I = copy.deepcopy(Z)
                    # j
                    I[same_sign[0][0],same_sign[0][1]] = -Csign[same_sign[0][2]][same_sign[0][3]]/pow(precision,2)
                    if oracle(program,I)==ztag:
                        '''
                        base + xCiWi = 0
                        base -B2Wj + yCiWi = 0
                        B2Wj = (y-x)CiWi    (B_proportion)
                        base + (x+sign(Ci))CiWi +zCjWj = 0
                        CjWj = -(sign(Ci))CiWi/z      (C_proportion)
                        Cj = -(sign(Ci))/z/(y-x)B2
                        Wj = (y-x)CiWi/B2   (B2=1)
                        '''
                        BASE2 = I
                        I = copy.deepcopy(BASE2)
                        # i
                        I[thres_diff[0][0][0],thres_diff[0][0][1]] = Csign[thres_diff[0][0][2]][thres_diff[0][0][3]]/pow(precision,2)
                        res = binsearch(program,precision,BASE2,I)
                        B_proportion = res[thres_diff[0][0][0],thres_diff[0][0][1]]-thres_diff[0][1]
                        
                        I = copy.deepcopy(BASE)
                        # j
                        I[same_sign[0][0],same_sign[0][1]] = Csign[same_sign[0][2]][same_sign[0][3]]/pow(precision,2)
                        res = binsearch(program,precision,BASE,I)
                        C_proportion = -Csign[Wbasis[2]][Wbasis[3]]/res[same_sign[0][0],same_sign[0][1]]
                        #C_proportion = -1./res[same_sign[0][0],same_sign[0][1]]
                        Cval[same_sign[0][2]][same_sign[0][3]] = float(C_proportion/B_proportion)
                        CvalFound[same_sign[0][2]][same_sign[0][3]] = True

                        Wval[same_sign[0][4]] = float(B_proportion*Cval[Wbasis[2]][Wbasis[3]]*Wval[Wbasis[2]*HORIZONTAL_WIDTH+Wbasis[3]])
                        WvalFound[same_sign[0][4]] = True
                else:
                    BASE = copy.deepcopy(Z)
                    BASE[Wbasis[0],Wbasis[1]] = thres_diff[0][1]+Csign[Wbasis[2]][Wbasis[3]]
                    thres_same = []
                    CW_ratio = []
                    for idx,point in enumerate(same_sign):
                        I = constructSign(BASE, point, Csign)
                        # B_f + (y * Ck + B2) * Wk + ((x + sign(Ci)) * Ci + B2) * Wi = base + yCkWk + 
                        res = binsearch(program,precision,BASE,I)
                        CW_ratio.append((point,res[point[0],point[1]]))
                        thres_same.append((point,res[point[0],point[1]]))
                    BASE = copy.deepcopy(Z)
                    BASE[thres_diff[0][0][0],thres_diff[0][0][1]] = thres_diff[0][1]
                    for idx,point in enumerate(thres_same):
                        '''
                        xCjWj+sign(Ci)CiWi = 0
                        yCkWk+sign(Ci)CiWi = 0
                        B2Wk = zCjWj
                        Ck = x/y/zB2  (B2=1)
                        '''
                        BASE2 = copy.deepcopy(BASE)
                        BASE2[point[0][0],point[0][1]] = -Csign[point[0][2]][point[0][3]]/pow(precision,2)
                        I = copy.deepcopy(BASE2)
                        helpPoint = thres_same[0] if idx != 0 else thres_same[1]
                        I[helpPoint[0][0],helpPoint[0][1]] = Csign[helpPoint[0][2]][helpPoint[0][3]]/pow(precision,2)
                        # base - CkWk + zCjWj
                        res = binsearch(program,precision,BASE2,I)
                        B_ratio = helpPoint[1]/point[1]/res[helpPoint[0][0],helpPoint[0][1]]
                        Cval[point[0][2]][point[0][3]] = float(B_ratio)
                        CvalFound[point[0][2]][point[0][3]] = True
                    for point in CW_ratio:
                        '''
                        xCjWj+sign(Ci)CiWi = 0
                        Wj = -sign(Ci)CiWi/x/Cj (Wi=+-1)
                        '''
                        Wval[point[0][4]] = float(-Csign[Wbasis[2]][Wbasis[3]]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex]/Cval[point[0][2]][point[0][3]]/point[1])
                        WvalFound[point[0][4]] = True
        else:
            # B_f + max(i * c_i + <->, 0) * w_i
            BASE = copy.deepcopy(Z)
            BASE[thres_diff[0][0][0],thres_diff[0][0][1]] = thres_diff[0][1]
            margin = thres_diff[0][1]
            while True:
                BASE2 = copy.deepcopy(BASE)
                BASE2[thres_diff[0][0][0],thres_diff[0][0][1]]-=margin
                assert oracle(program,BASE2)==ztag
                I = copy.deepcopy(BASE2)
                I[diff_sign[1][0],diff_sign[1][1]] = Csign[diff_sign[1][2]][diff_sign[1][3]]/pow(precision,2)
                res = binsearch(program,precision,BASE2,I)
                # B_f + (i * Ci + B2) * Ci + (j * Cj + B2) * Cj
                I = copy.deepcopy(res)
                I[thres_diff[0][0][0],thres_diff[0][0][1]] = 0
                # B_f + (j * Cj + B2) * Cj
                if oracle(program,I)==ztag:
                    break
                margin/=2
            BASE[thres_diff[0][0][0],thres_diff[0][0][1]]-=margin/2
            assert oracle(program,BASE)==ztag

            CW_ratio = []
            thres_diff_margin = []
            for idx,point in enumerate(diff_sign[1:]):  #get CiWi:CjWj  #(XiCi+B2)Wi ~ ()
                I = copy.deepcopy(BASE)
                I[point[0],point[1]] = Csign[point[2]][point[3]]/pow(precision,2)
                res1 = binsearch(program,precision,BASE,I)
                I = copy.deepcopy(BASE2)
                I[point[0],point[1]] = Csign[point[2]][point[3]]/pow(precision,2)
                res2 = binsearch(program,precision,BASE2,I)
                thres_diff_margin.append((point,res1[point[0],point[1]],res2[point[0],point[1]]))
                CW_ratio.append((point,res2[point[0],point[1]]-res1[point[0],point[1]]))
            for point in thres_diff_margin:
                '''
                base+(xCi+B2)Wi = 0
                assert (x-2*M)Ci+B2 > 0
                base+((x-M)Ci+B2)Wi+(yCj+B2)Wj = 0
                base+((x-2M)Ci+B2)Wi+(zCj+B2)Wj = 0
                MCiWi = yCjWj+B2Wj
                MCiWi = (z-y)CjWj
                (y-(z-y))CjWj = -B2Wj
                Cj = -B2/(y-(z-y))   (B2=-1)
                '''
                B_ratio = point[1]-(point[2]-point[1])
                Cval[point[0][2]][point[0][3]] = float(1./B_ratio)
                CvalFound[point[0][2]][point[0][3]] = True

            margin2 = 1./Cval[thres_diff[1][0][2]][thres_diff[1][0][3]]
            margin2/=2
            BASE = copy.deepcopy(Z)
            BASE[thres_diff[1][0][0],thres_diff[1][0][1]] = thres_diff[1][1]-margin2/2
            BASE2 = copy.deepcopy(BASE)
            BASE2[thres_diff[1][0][0],thres_diff[1][0][1]]-=margin2/2
            I = copy.deepcopy(BASE)
            I[thres_diff[0][0][0],thres_diff[0][0][1]] = Csign[thres_diff[0][0][2]][thres_diff[0][0][3]]/pow(precision,2)
            res1 = binsearch(program,precision,BASE,I)
            I = copy.deepcopy(BASE2)
            I[thres_diff[0][0][0],thres_diff[0][0][1]] = Csign[thres_diff[0][0][2]][thres_diff[0][0][3]]/pow(precision,2)
            res2 = binsearch(program,precision,BASE2,I)
            B_ratio = res1[thres_diff[0][0][0],thres_diff[0][0][1]]-\
                      (res2[thres_diff[0][0][0],thres_diff[0][0][1]]-\
                       res1[thres_diff[0][0][0],thres_diff[0][0][1]])
            Cval[thres_diff[0][0][2]][thres_diff[0][0][3]] = float(1./B_ratio)
            CvalFound[point[0][2]][point[0][3]] = True
            for point in CW_ratio:
                '''
                base+(xCi+B2)Wi = 0
                assert (x-2*M)Ci+B2 > 0
                base+((x-M)Ci+B2)Wi+(yCj+B2)Wj = 0
                base+((x-2M)Ci+B2)Wi+(zCj+B2)Wj = 0
                MCiWi = yCjWj+B2Wj
                MCiWi = (z-y)CjWj
                Wj = MCiWi/(z-y)/Cj
                '''
                Wval[point[0][4]] = float((margin/2)*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex]/(point[1]*Cval[point[0][2]][point[0][3]]))
                WvalFound[point[0][4]] = True
            Zval = float(-(thres_diff[0][1]*Cval[Wbasis[2]][Wbasis[3]]+C_Bias)*Wval[WbasisIndex])

            if len(same_sign)!=0:
                BASE = copy.deepcopy(Z)
                BASE[thres_diff[0][0][0],thres_diff[0][0][1]] = thres_diff[0][1]
                BASE2 = copy.deepcopy(BASE)
                BASE2[thres_diff[0][0][0],thres_diff[0][0][1]]+=Csign[thres_diff[0][0][2]][thres_diff[0][0][3]]
                thres_same = []
                CW_ratio = []
                for idx,point in enumerate(same_sign):
                    I1 = copy.deepcopy(BASE)
                    I2 = copy.deepcopy(BASE)
                    I1[point[0],point[1]] = 1./pow(precision,2)
                    I2[point[0],point[1]] = -1./pow(precision,2)
                    res1 = oracle(program,I1)
                    res2 = oracle(program,I2)
                    if res1==ztag:
                        Csign[point[2]][point[3]] = 1
                    elif res2==ztag:
                        Csign[point[2]][point[3]] = -1
                    else:
                        return
                    I = copy.deepcopy(BASE)
                    I[point[0],point[1]] = Csign[point[2]][point[3]]/pow(precision,2)
                    res = binsearch(program,precision,BASE,I)
                    thres_same.append((point,res[point[0],point[1]]))
                    I = copy.deepcopy(BASE2)
                    I[point[0],point[1]] = Csign[point[2]][point[3]]/pow(precision,2)
                    res = binsearch(program,precision,BASE2,I)
                    CW_ratio.append((point,thres_same[idx][1]-res[point[0],point[1]]))
                for point in thres_same:
                    '''
                    (xCj+B2)Wj = 0
                    Cj = -B2/x
                    '''
                    Cval[point[0][2]][point[0][3]] = float(1./point[1])
                    CvalFound[point[0][2]][point[0][3]] = True
                for point in CW_ratio:
                    '''
                    (xCj+B2)Wj = 0
                    (yCj+B2)Wj+(sign(Ci))CiWi = 0
                    (x-y)CjWj = (sign(Ci))CiWi
                    Wj = (sign(Ci))CiWi/(x-y)/Cj
                    '''
                    Wval[point[0][4]] = float(Csign[Wbasis[2]][Wbasis[3]]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex]/(point[1]*Cval[point[0][2]][point[0][3]]))
                    WvalFound[point[0][4]] = True

        ##### Construct the rest #####
        # (input.shape[0], input.shape[1], kernel.shape[0], kernel.shape[1], w, w's left-top kernel, w's left-top kernel)
        cases = (((0,1,0,1,1),[(0,0,0,0,0)]),
                 ((1,0,1,0,3),[(0,0,0,0,0)]),
                 ((0,5,0,3,1),[(0,6,0,4,2)]),
                 ((1,6,1,4,5),[(0,6,0,4,2)]),
                 ((5,0,3,0,3),[(6,0,4,0,6)]),
                 ((6,1,4,1,7),[(6,0,4,0,6)]),
                 ((5,6,3,4,5),[(6,6,4,4,8)]),
                 ((6,5,4,3,7),[(6,6,4,4,8)]),

                 ((1,1,1,1,4),[(0,0,0,0,0),(0,1,0,1,1,0,1),(1,0,1,0,3,1,0)]),
                 ((0,2,0,2,2),[(0,0,0,0,0),(0,1,0,1,1,0,1)]),
                 ((2,0,2,0,6),[(0,0,0,0,0),(1,0,1,0,3,1,0)]),
                 ((6,4,4,2,6),[(6,6,4,4,8),(6,5,4,3,7,2,1)]),
                 ((4,6,2,4,2),[(6,6,4,4,8),(5,6,3,4,5,1,2)]),
                 ((1,5,1,3,4),[(0,6,0,4,2),(0,5,0,3,1,0,1),(1,6,1,4,5,1,2)]), #
                 ((5,1,3,1,4),[(6,0,4,0,6),(5,0,3,0,3,1,0),(6,1,4,1,7,2,1)]),
                 ((5,5,3,3,4),[(6,6,4,4,8),(5,6,3,4,5,1,2),(6,5,4,3,7,2,1)]),
                 )

        for case in cases:
            BASE = copy.deepcopy(Z)
            point, pivots = case
            Windex = point[4]
            pivot = pivots[0]
            pivotWIndex = pivot[4]
            BASE[pivot[0],pivot[1]] = -Csign[pivot[2]][pivot[3]]/pow(precision,4)
            for p in pivots[1:]:
                BASE[p[0],p[1]] = -Csign[pivot[2]][pivot[3]]/pow(precision,3)
            initial = oracle(program,BASE)
            I = copy.deepcopy(BASE)
            I[point[0],point[1]] = Csign[pivot[2]][pivot[3]]/pow(precision,2)
            res = oracle(program,I)
            if Wsign[pivotWIndex]*Zval>0:
                if res==ztag:
                    # print(f'point={point}, if/if')
                    #W1, W2 same sign as base
                    # if Wval[Windex] == 0:
                    if True:
                        Wsign[Windex] = ztag*2-1
                        if C_Bias<0:
                            thres = -Zval/Wval[WbasisIndex]
                            thres = (thres-C_Bias)/Cval[Wbasis[2]][Wbasis[3]]
                        else:
                            removeW = C_Bias*Wval[pivotWIndex]
                            for p in pivots[1:]:
                                removeW += C_Bias*Wval[p[4]]
                            thres = (-Zval+removeW)/Wval[WbasisIndex]
                            thres = thres/Cval[Wbasis[2]][Wbasis[3]]
                        '''
                        #cleaner way to derive thres, but takes up more queries
                        I = copy.deepcopy(BASE)
                        I[Wbasis[0],Wbasis[1]] = 1./pow(precision,2)
                        res = binsearch(program,precision,BASE,I)
                        thres = res[Wbasis[0],Wbasis[1]]
                        #print(thres)
                        '''
                        BASE[Wbasis[0],Wbasis[1]] = thres+Csign[Wbasis[2]][Wbasis[3]]
                        I = copy.deepcopy(BASE)
                        I[point[0],point[1]] = Csign[pivot[2]][pivot[3]]/pow(precision,2)
                        # (yCj + B2)Wj + ((x+sign(Ci)Ci+B2)Wi)
                        res = binsearch(program,precision,BASE,I)
                        if C_Bias<0:
                            '''
                            # base = B_f
                            base + (xCi+B2)Wi = 0
                            base + (yCj+B2)Wj + ((x+sign(Ci))Ci+B2)Wi = 0
                            sign(Ci)CiWi = -(yCj+B2)Wj
                            Wj = -sign(Ci)CiWi/(yCj+B2)
                            '''
                            Wval[Windex] = float(-Csign[Wbasis[2]][Wbasis[3]]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex]/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]+C_Bias))
                        else:
                            '''
                            # base = B_f + sigma W_all * B2
                            base + xCiWi = 0
                            base + yCjWj + (x+sign(Ci))CiWi = 0
                            sign(Ci)CiWi = -yCjWj
                            Wj = -sign(Ci)CiWi/yCj
                            '''
                            Wval[Windex] = float(-Csign[Wbasis[2]][Wbasis[3]]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex]/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]))
                        WvalFound[Windex] = True

                    '''
                    # previous j is now k
                    C_Bias < 0
                        base+(yCk+B2)Wk+((x+sign(Ci))Ci+B2)Wi = 0
                        base+(zCk+()+yCj+B2)Wj+((x+2sign(Ci))Ci+B2)Wi+(yCk+B2)Wk= 0
                        sign(Ci)CiWi = -(zCk+()+yCj+B2)Wj
                        zCk+()+yCj = -sign(Ci)CiWi/Wj-B2
                        Cj = (-sign(Ci)CiWi)/Wj-B2-zCk-())/y    (B2=-1)

                    C_Bias > 0
                        base+(yCk)Wk+((x+sign(Ci))Ci)Wi-<B2Wpivots[1:]>-B2Wj = 0
                        base+(zCk+()+yCj)Wj+(x+2sign(Ci))CiWi+yCkWk-<> = 0
                        sign(Ci)CiWi = -(zCk+()+yCj+B2)Wj
                        Cj = (-sign(Ci)CiWi/Wj-B2-zCk-())/y    (B2=1)

                    '''

                    BASE = res
                    BASE[Wbasis[0],Wbasis[1]]+=Csign[Wbasis[2]][Wbasis[3]]
                    others = 0
                    for p in pivots[1:]:
                        BASE[p[0],p[1]] = (-BASE[point[0],point[1]]*Cval[point[0]-p[5]][point[1]-p[6]]-C_Bias)/Cval[pivot[2]][pivot[3]]-Csign[pivot[2]][pivot[3]]
                        others += BASE[p[0],p[1]] * Cval[p[2]][p[3]]
                    BASE[pivot[0],pivot[1]] = -Csign[pivot[2]][pivot[3]]/pow(precision,2)
                    I = copy.deepcopy(BASE)
                    I[pivot[0],pivot[1]] = Csign[pivot[2]][pivot[3]]/pow(precision,2)
                    res = binsearch(program,precision,BASE,I)
                    Cval[point[2]][point[3]] = float(((-Csign[Wbasis[2]][Wbasis[3]]*Cval[Wbasis[2]][Wbasis[3]]*Wval[WbasisIndex])/Wval[pivotWIndex]-C_Bias-res[pivot[0],pivot[1]]*Cval[pivot[2]][pivot[3]]-others)/res[point[0],point[1]])
                    CvalFound[point[2]][point[3]] = True
                    if Cval[point[2]][point[3]]>0:
                        Csign[point[2]][point[3]] = 1
                    else:
                        Csign[point[2]][point[3]] = -1

                else:
                    # print(f'point={point}, if/else')
                    #W1 same sign as base, W2 diff sign as base
                    if Wval[Windex] == 0:
                        Wsign[Windex] = (1-ztag)*2-1
                        res = binsearch(program,precision,BASE,I)
                        # oracle(program,res,True)
                        if C_Bias<0:
                            '''
                            Zval + (xC1+B2)W2 = 0
                            W2 = -Zval/(xC1+B2)
                            '''
                            Wval[Windex] = float(-Zval/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]+C_Bias))
                            WvalFound[Windex] = True
                        else:
                            '''
                            Zval - B2W1 - {} + xC1W2 = 0
                            W2 = (-Zval+B2W1)/xC1
                            '''
                            tmp = 0
                            for p in pivots[1:]:
                                tmp += C_Bias*Wval[p[2]*HORIZONTAL_WIDTH+p[3]]
                            Wval[Windex] = float((-Zval+C_Bias*Wval[pivotWIndex]+tmp)/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]))
                            WvalFound[Windex] = True

                    '''
                    if B2>0:
                        base + yC1W2 + (xC1 + {pivotsC} +yC2)W1 + {-B2Wp} = 0
                        C2 = ((-base-yC1W2-{})/W1-xC1-{})/y
                    else:
                        base + (yC1+B2)W2 + (xC1 + {pivotsC} +yC2 + B2)W1 = 0
                        C2 = ((-base-(yC1+B2)W2)/W1-xC1-{}-B2)/y
                    '''
                    BASE = copy.deepcopy(Z)
                    if C_Bias<0:
                        thres = -Zval/Wval[Windex]
                        thres = (thres-C_Bias)/Cval[pivot[2]][pivot[3]]
                    else:
                        removeW = 0
                        for p in pivots[1:]:
                            removeW += C_Bias*Wval[p[4]]
                        thres = (-Zval+removeW)/Wval[Windex]
                        thres = thres/Cval[pivot[2]][pivot[3]]
                    BASE[point[0],point[1]] = thres+Csign[pivot[2]][pivot[3]]
                    others, w1others = 0, 0
                    for p in pivots[1:]:
                        BASE[p[0],p[1]] = (-BASE[point[0],point[1]]*Cval[point[0]-p[5]][point[1]-p[6]]-C_Bias)/Cval[pivot[2]][pivot[3]]-Csign[pivot[2]][pivot[3]]
                        w1others += BASE[p[0],p[1]] * Cval[p[2]][p[3]]
                        others -= Wval[p[4]] * C_Bias if C_Bias > 0 else 0
                    BASE[pivot[0],pivot[1]] = -Csign[pivot[2]][pivot[3]]/precision
                    I = copy.deepcopy(BASE)
                    I[pivot[0],pivot[1]] = Csign[pivot[2]][pivot[3]]/precision
                    res = binsearch(program,precision,BASE,I)
                    if C_Bias>0:
                        Cval[point[2]][point[3]] = float(((-Zval-res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]*Wval[Windex]-others)/Wval[pivotWIndex]-res[pivot[0],pivot[1]]*Cval[pivot[2]][pivot[3]]-w1others)/res[point[0],point[1]])
                    else:
                        Cval[point[2]][point[3]] = float(((-Zval-(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]+C_Bias)*Wval[Windex]-others)/Wval[pivotWIndex]-res[pivot[0],pivot[1]]*Cval[pivot[2]][pivot[3]]-w1others-C_Bias)/res[point[0],point[1]])
                    Csign[point[2]][point[3]] = 1 if Cval[point[2]][point[3]]>0 else -1
                
                        
            
            else:
                if res==ztag:
                    # print(f'point={point}, else/if')
                    #W2 is of different sign as W1
                    if Wval[Windex] == 0:
                        Wsign[Windex] = -Wsign[pivotWIndex]
                        '''
                        if B2>0:
                            base - B2W1 - {B2Wpivots[1:]} + TCkWk + xC1W2 = 0
                            W2 = (-base+B2W1+{}-TCkWk)/(xC1)
                        else:
                            base + (TCk+B2)Wk + (xC1+B2)W2 = 0
                            W2 = (-base-(TCk+B2)Wk)/(xC1+B2)
                        '''
                        diffPoint = Wbasis if Wbasis != pivot else diff_sign[1]
                        I = copy.deepcopy(BASE)
                        I[diffPoint[0],diffPoint[1]] = Csign[diffPoint[2]][diffPoint[3]]/pow(precision,2)
                        res = binsearch(program,precision,BASE,I)
                        BASE[diffPoint[0],diffPoint[1]] = res[diffPoint[0],diffPoint[1]] + Csign[diffPoint[2]][diffPoint[3]]
                        I = copy.deepcopy(BASE)
                        I[point[0],point[1]] = Csign[pivot[2]][pivot[3]]/pow(precision,2)
                        res = binsearch(program,precision,BASE,I)
                        removeW = 0
                        for p in pivots[1:]:
                            removeW += C_Bias * Wval[p[2]*HORIZONTAL_WIDTH+p[3]]
                        if C_Bias>0:
                            Wval[Windex] = float((-Zval+C_Bias*Wval[pivotWIndex]+removeW-res[diffPoint[0],diffPoint[1]]*Cval[diffPoint[2]][diffPoint[3]]*Wval[diffPoint[4]])/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]))
                        else:
                            Wval[Windex] = float((-Zval-(res[diffPoint[0],diffPoint[1]]*Cval[diffPoint[2]][diffPoint[3]]+C_Bias)*Wval[diffPoint[4]])/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]+C_Bias))
                    
                else:
                    # print(f'point={point}, else/else')
                    #W1 is same sign as W2
                    if Wval[Windex] == 0:
                        Wsign[Windex] = Wsign[pivotWIndex]
                        res = binsearch(program,precision,BASE,I)
                        if C_Bias>0:
                            '''
                            base-B2Wi-{B2W?}+xCiWj = 0
                            Wj = (-base+B2Wi)/xCi
                            '''
                            removeW = C_Bias*Wval[pivotWIndex]
                            for p in pivots[1:]:
                                removeW += C_Bias*Wval[p[2]*HORIZONTAL_WIDTH+p[3]]
                            Wval[Windex] = float((-Zval+removeW)/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]))
                        else:
                            '''
                            base+(xCi+B2)Wj = 0
                            Wj = -base/(xCi+B2)
                            '''
                            Wval[Windex] = float(-Zval/(res[point[0],point[1]]*Cval[pivot[2]][pivot[3]]+C_Bias))
                        WvalFound[Windex] = True

                '''
                if B2>0:
                    base - B2W2 + <-B2{Wpivots[1:]} + zCkWk> + (xCi+yC2+{pivots[1:]C?})W1 = 0
                    C2 = ((-base+B2W2-<>)/W1-xCi-{})/y
                else:
                    base + <(zCk+B2)Wk> + (xCi+yC2+{pivots[1:]C?}+B2)W1 = 0
                    C2 = ((-base-<>)/W1-xCi-{}-B2)/y
                '''
                BASE = copy.deepcopy(Z)
                BASE[point[0],point[1]] = -C_Bias/Cval[pivot[2]][pivot[3]]-Csign[pivot[2]][pivot[3]]
                others = 0
                for p in pivots[1:]:
                    BASE[p[0],p[1]] = (-BASE[point[0],point[1]]*Cval[point[0]-p[5]][point[1]-p[6]]-C_Bias)/Cval[pivot[2]][pivot[3]]-Csign[pivot[2]][pivot[3]]
                    others -= Wval[p[4]] * C_Bias if C_Bias > 0 else 0
                if oracle(program,BASE) != ztag:
                    if len(same_sign) < 1:
                        print('try again')
                        return
                    # print('use samePoint')
                    # k = samePoint
                    samePoint = same_sign[0]
                    I = copy.deepcopy(BASE)
                    I[samePoint[0],samePoint[1]] = Csign[samePoint[2]][samePoint[3]]/pow(precision,2)
                    res = binsearch(program,precision,BASE,I)
                    BASE[samePoint[0],samePoint[1]] = res[samePoint[0],samePoint[1]] + Csign[samePoint[2]][samePoint[3]]
                    tmp = BASE[samePoint[0],samePoint[1]]*Cval[samePoint[2]][samePoint[3]]
                    tmp += C_Bias if C_Bias < 0 else 0
                    others += tmp * Wval[samePoint[4]]
                I = copy.deepcopy(BASE)
                I[pivot[0],pivot[1]] = Csign[pivot[2]][pivot[3]]/pow(precision,2)
                res = binsearch(program,precision,BASE,I)
                tmp = 0
                for p in pivots[1:]:
                    tmp += res[p[0],p[1]] * Cval[p[2]][p[3]]
                if C_Bias>0:
                    Cval[point[2]][point[3]] = float(((-Zval+C_Bias*Wval[Windex]-others)/Wval[pivotWIndex]\
                        -res[pivot[0],pivot[1]]*Cval[pivot[2]][pivot[3]]-tmp)\
                        /res[point[0],point[1]])
                else:
                    Cval[point[2]][point[3]] = float(((-Zval-others)/Wval[pivotWIndex]-res[pivot[0],pivot[1]]*Cval[pivot[2]][pivot[3]]-tmp-C_Bias)/res[point[0],point[1]])
                Csign[point[2]][point[3]] = 1 if Cval[point[2]][point[3]] > 0 else -1
                CvalFound[point[2]][point[3]] = True
        debug()
        #constructFlag(Cval)

    except Exception as e:
        print(e)
        return

    program.close()
    constructFlag(Cval)

####

from collections import defaultdict
buckets = [defaultdict(int) for _ in range(25)]
count = 0

def constructFlag(Cval):
    global buckets, count
    Cval = np.array(Cval).reshape(-1) * 1e7
    Cval = Cval.astype('int')
    flagprefix = [ord(x) for x in 'BALSN{']
    prev = []
    range_ = range(9999990,1000000,-1) if Cval[0] > 0 else range(-9999990,-1000000)
    for i in range_:
        scale1 = i / Cval[0]
        if scale1 > 1 or scale1 < -1:
            continue
        guess = Cval * scale1
        if ((guess[0]+1e7) % 10000 / 10) == 0:
            continue
        scale2 = flagprefix[0] / ((guess[0]+1e7) % 10000 / 10)
        check = 0
        for j in range(1,6):
            if flagprefix[j]-1 <= ((guess[j]+1e7) % 10000) * scale2 / 10 <= flagprefix[j]+1:
                check += 1
        if check == 5:
            get = [int(round(((guess[j]+1e7) % 10000) * scale2 / 10)) for j in range(25)]
            if get != prev:
                for j in range(25):
                    ch = chr(get[j])
                    buckets[j][ch] += 1
                prev = get
    if prev != []:
        count += 1


while count < 3:
    print('solving...')
    solve()

for j in range(25):
    print(buckets[j])

input('======')
###busy making other challenges and didn't have time to impl final bruteforce...
