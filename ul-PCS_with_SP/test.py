#!/usr/bin/env python3.8.3

from charm.toolbox.pairinggroup import PairingGroup
from main import UPCS
from policy import Policy
import time
import sys
groupObj = PairingGroup('BN254')
F_lambda = Policy()
UPCS = UPCS(groupObj)



def main(n_R,x,y):
    '''
    Policy maker
    '''
    F=F_lambda.maker(n_R)

    '''
    This command ensures the policy for role x and role y fulfills.
    '''
    F['R'][y]=1; F['R'][x]=1; F['S'][y]=1; F['S'][x]=1
    
    '''
    To Setup the master secret key and master public key
    '''
    t=time.time()
    (msk, mpk) = UPCS.Setup()
    print("The setup for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    KeyGen algorithm for the sender
    '''
    sk={};pk={}
    t=time.time()
    (sk[0],pk[0],LT1) = UPCS.KeyGen(mpk,msk,x,F)
    print("The key generation for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    KeyGen algorithm to create the receiver's key
    '''
    sk_R={};pk_R={}
    (sk_R[0],pk_R[0],LT1) = UPCS.KeyGen(mpk,msk,y,F)

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
    sigma,LT2 = UPCS.Sign(mpk,sk[1],pk_R[1],m, LT1)
    print("The signing for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''
    t=time.time()
    out = UPCS.verify(mpk,pk[1],pk_R[1],m,sigma,LT1,LT2)
    print("The verification for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    t=time.time()
    out = UPCS.Batched_verify(mpk,pk[1],pk_R[1],m,sigma,LT1,LT2)
    print("The Batched verification for {} attributes/roles took {:0.4f} seconds".format(n_R,time.time()-t))

    if out==True:
        print('The signature is valid.\n')
    else:
        print('The signature is not valid.\n')



'''
You can adjust the size of policy matrix by changing n_R
'''
n_R=int(sys.argv[1])
main(n_R,3,2)
