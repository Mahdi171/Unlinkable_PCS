#!/usr/bin/env python3.8.3
from charm.toolbox.pairinggroup import PairingGroup,pair
from main import PCS
from BLS import BLS01 as DS
import numpy as np
from BG import BG
from SPS import SPS
from GS import GS as NIZK
from OT12 import OT as FE
import time
import sys
groupObj = PairingGroup('BN254')
DS = DS(groupObj)
BG = BG(groupObj)
NIZK = NIZK(groupObj)
SPS = SPS(groupObj)
PCS = PCS(groupObj)

def main(N,x,v):
    '''
    To Setup the master secret key and master public key
    '''
    t=time.time()
    (msk, mpk) = PCS.Setup(N,x,v)
    print("The setup for {} attributes/roles took {:0.4f} seconds".format(int((N-2)/4),time.time()-t))


    '''
    KeyGen algorithm for the sender
    '''
    t=time.time()
    (sk_S,pk_S) = PCS.KeyGen(mpk,msk,x)
    print("The key generation for {} attributes/roles took {:0.4f} seconds".format(int((N-2)/4),time.time()-t))
   
    '''
    KeyGen algorithm to create the receiver's key
    '''

    (sk_R,pk_R) = PCS.KeyGen(mpk,msk,v)
 

    '''
    To sign a random integer m under the secret key sk and public key pk_R
    '''
    m = groupObj.random()
    t=time.time()
    (sigma,LT) = PCS.Sign(mpk,sk_S,pk_R,m)
    print("The signing for {} attributes/roles took {:0.4f} seconds".format(int((N-2)/4),time.time()-t))

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''
    t = time.time()
    out = PCS.verify(mpk,pk_S,pk_R,m,sigma)
    print("The verification for {} attributes/roles took {:0.4f} seconds".format(int((N-2)/4),time.time()-t))

    t = time.time()
    out = PCS.Batched_verify(mpk,pk_S,pk_R,m,sigma)
    print("The Batched verification for {} attributes/roles took {:0.4f} seconds".format(int((N-2)/4),time.time()-t))

    if out==True:
        print('The signature is valid.\n')
    else:
        print('The signature is not valid.\n')



'''
You can adjust the number of attributes by changing n
'''

n=int(sys.argv[1]) #number of attributes
v=[groupObj.random() for _ in range(n-1)]
x=[groupObj.random() for _ in range(n-1)]
p=groupObj.order()
v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
x.append(1)
prod = np.sum([x * y for x, y in zip(v, x)]) 
print('IP(x,v)={}'.format(prod))



main(4*n+2,x,v)