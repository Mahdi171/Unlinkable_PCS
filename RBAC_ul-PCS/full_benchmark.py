from random import random
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import objectToBytes
from Acc import ACC
from SPSEQ import SPSEQ as SEQ
from BLS import BLS01 as DS
from openpyxl import Workbook
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com
from openpyxl import Workbook
import os
from charm.core.engine.util import serializeDict,objectToBytes,serializeObject
import numpy as np
from main import UPCS
import sys

groupObj = PairingGroup('BN254')
ACC = ACC(groupObj)
SEQ = SEQ(groupObj)
DS = DS(groupObj)
BG = BG(groupObj)
PRF = PRF(groupObj)
NIZK = NIZK(groupObj)
Sigma= Sigma(groupObj)
SPS = SPS(groupObj)
RangeProof = RangeProof()
UPCS = UPCS(groupObj)
def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime", "Pair"])

def end_bench(group):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    real_time = benchmarks['RealTime'], benchmarks["Pair"]
    return real_time


class Full_benchmark(): 
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)        
        group = groupObj    
    def main(self,n_R,iter):
        result=[n_R]  
        x=3 # the sender i=2, any role in range [1,n_R]
        y=2 # the receiver j=1.
        #CA Key Gen
        setup_time=0
        F=Policy.maker(self,n_R)
        for i in range(n_R):
            F[i,i]=1
        F[1,2]=1; F[2,1]=1 #to make sure receiver j=3 and sender i=3 are allowed to have a link
        for i in range(iter):
            start_bench(groupObj)
            (msk, mpk) = UPCS.Setup(F,x,y)
            setup_time1, setup_pair= end_bench(groupObj)
            setup_time += setup_time1
        result.append(setup_time/iter)
        file = open("/app/RBAC/parameters/RBACmsk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(msk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/RBAC/parameters/RBACmsk_{}.txt".format(n_R))/1000)
        
        
        file = open("/app/RBAC/parameters/RBACmpk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(mpk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/RBAC/parameters/RBACmpk_{}.txt".format(n_R))/1000)
        pk={};sk={}



        KeyGen_time=0
        for i in range(iter):
            start_bench(groupObj)
            (sk[0],pk[0],LT1) = UPCS.KeyGen(mpk,msk,x)
            KeyGen_time1, keygen_pair = end_bench(groupObj)
            KeyGen_time += KeyGen_time1
        result.append(KeyGen_time/iter)
        
        
        file = open("/app/RBAC/parameters/RBACsk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(sk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/RBAC/parameters/RBACsk_{}.txt".format(n_R))/1000)
        
        file = open("/app/RBAC/parameters/RBACpk_{}.txt".format(n_R), "w") 
        str = repr(pk)
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/RBAC/parameters/RBACpk_{}.txt".format(n_R))/1000)

        sk_R={};pk_R={}
        (sk_R[0],pk_R[0],LT1) = UPCS.KeyGen(mpk,msk,y)

        # Receivers' key re-randomization
        RandKey_time=0
        for i in range(iter):
            start_bench(groupObj)
            (sk[i+1],pk[i+1],LT1) = UPCS.RandKey(mpk,sk[i])
            RandKey_time1, Rand_pair = end_bench(groupObj)
            RandKey_time += RandKey_time1
        result.append(RandKey_time/iter)

        #Pre-processing Sign
        
        m = group.random()

        #Sign
        Sign_time=0
        for i in range(iter):
            start_bench(groupObj)
            sigma,LT2 = UPCS.Sign(mpk,sk[1],pk_R[0],m,x)
            Sign_time1, Sign_pair= end_bench(groupObj)
            Sign_time += Sign_time1
        result.append(Sign_time/iter)


        file = open("/app/RBAC/parameters/RBACSig_{}.txt".format(n_R), "w")
        file.write(repr(sigma))
        file.close()
        result.append(os.path.getsize("/app/RBAC/parameters/RBACSig_{}.txt".format(n_R))/1000)

        # Verification time
        Verify_time = 0
        for i in range(iter):
            start_bench(groupObj)
            out = UPCS.verify(mpk,pk[1],pk_R[0],m,sigma)
            Verify_time1, verify_pair = end_bench(groupObj)
            Verify_time += Verify_time1
        result.append(Verify_time/iter)
        #result.append(PPSign_time)
        result.append(verify_pair)
        
        # Verification time
        Batched_Verify_time=0
        for i in range(iter):
            start_bench(groupObj)
            out = UPCS.Batched_verify(mpk,pk[1],pk_R[0],m,sigma)
            print("Signature is ",out)
            Batched_Verify_time1, Batched_pair = end_bench(groupObj)
            Batched_Verify_time += Batched_Verify_time1
        result.append(Batched_Verify_time/iter)
        result.append(Batched_pair)


        return result

book = Workbook()
data = book.active
title = ["N","Setup_time", "msk_size", "mpk_size", "KeyGen_time" ,"sk_size",\
    "pk_size", "RandKey_time", "Sign_time", "sig_size" ,"Verify_time", "Verify_pair",\
        "Batched_Verify_time", "Batched_Verify_pair"]
data.append(title)
Full_benchmark=Full_benchmark(groupObj)

for n_R in range(int(sys.argv[1]),int(sys.argv[2])+1,int(sys.argv[3])): #Use can change this range
    data.append(Full_benchmark.main(n_R,int(sys.argv[4])))
    print(n_R,"\n")
book.save("RBAC.xlsx")