from charm.toolbox.pairinggroup import PairingGroup,pair
from main import UPCS
from Acc import ACC
from SPSEQ import SPSEQ
from BLS import BLS01
from BG import BG
from policy import Policy
from PRF import DY
from GS import GS
from SPS import SPS
import os
import sys
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom
from charm.core.engine.util import serializeDict,objectToBytes,serializeObject
from openpyxl import Workbook
import os
import time
groupObj = PairingGroup('BN254')
ACC = ACC(groupObj)
SEQ = SPSEQ(groupObj)
DS = BLS01(groupObj)
BG = BG(groupObj)
F_lambda = Policy()
PRF = DY(groupObj)
NIZK = GS(groupObj)
Sigma= Sigma(groupObj)
SPS = SPS(groupObj)
RangeProof = RangeProof()
Com = PedCom(groupObj)
UPCS = UPCS(groupObj)

def main(n_R,x,y):
    '''
    Policy maker
    '''
    F=F_lambda.maker(n_R)

    '''
    This command ensures the policy for role x and role y fulfills.
    '''
    F[x,y]=1; F[y,x]=1 
    
    '''
    To Setup the master secret key and master public key
    '''
    t=time.time()
    (msk, mpk) = UPCS.Setup(F,x,y)
    print("The setup for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))


    '''
    KeyGen algorithm for the sender
    '''
    sk={};pk={}
    t=time.time()
    (sk[0],pk[0],LT1) = UPCS.KeyGen(mpk,msk,x)
    print("The key generation for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    KeyGen algorithm to create the receiver's key
    '''
    sk_R={};pk_R={}
    (sk_R[0],pk_R[0],LT1) = UPCS.KeyGen(mpk,msk,y)

    '''
    senders' key re-randomization
    '''
    t=time.time()
    (sk[1],pk[1],LT1) = UPCS.RandKey(mpk,sk[0])
    print("The key randomization for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    Receiver's key re-randomization
    '''
    (sk_R[1],pk_R[1],LT1) = UPCS.RandKey(mpk,sk_R[0])
    
    '''
    To sign a random integer m under the secret key sk and public key pk_R
    '''
    m = groupObj.random()
    t=time.time()
    sigma,LT2 = UPCS.Sign(mpk,sk[1],pk_R[1],m,x)
    print("The Signing for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''

    t=time.time()
    out = UPCS.verify(mpk,pk[1],pk_R[1],m,sigma)
    print("The verification for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))


    t=time.time()
    out = UPCS.Batched_verify(mpk,pk[1],pk_R[1],m,sigma)
    print("The batched verification for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    if out==True:
        print('The signature is valid.\n')
    else:
        print('The signature is not valid.\n')



'''
You can adjust the size of policy matrix by changing n_R
'''
n_R=int(sys.argv[1])
main(n_R,3,2)