from random import random
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import objectToBytes
from BLS import BLS01 as DS
from BG import BG
from PRF import DY as PRF
from OT12 import OT as FE
from SPS import SPS
from GS import GS as NIZK
from Pedersen import PedCom as Com
from SPSEQ import SPSEQ as SEQ
from Sigma import Sigma
from Bulletproof import RangeProof
from Acc import ACC
from Pedersen import GPed
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
Com = GPed(groupObj)
UPCS = UPCS(groupObj)
FE = FE(groupObj)
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
    def main(self,n,N,iter):
        result=[N,n]
        v = [group.random(ZR) for _ in range(n-1)]
        x = [group.random(ZR) for _ in range(n-1)]
        p = group.order()
        v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
        x.append(1)
        prod = np.sum([x * y for x, y in zip(v, x)]) 
        print('IP(x,v)={}'.format(prod))
        #CA Key Gen
        setup_time=0
        for i in range(iter):
            start_bench(groupObj)
            (msk, mpk) = UPCS.Setup(N)
            setup_time1, setup_pair= end_bench(groupObj)
            setup_time += setup_time1
        result.append(setup_time/iter)

        


        file = open("app/Generic/parameters/Genericmsk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(msk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("app/Generic/parameters/Genericmsk_{}.txt".format(n_R))/1000)

        file = open("app/Generic/parameters/Genericmpk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(mpk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("app/Generic/parameters/Genericmpk_{}.txt".format(n_R))/1000)


        KeyGen_time=0
        for i in range(iter):
            pk = {}; sk = {}
            start_bench(groupObj)
            (sk[0],pk[0],LT1) = UPCS.KeyGen(mpk,msk,v)
            KeyGen_time1, keygen_pair = end_bench(groupObj)
            KeyGen_time += KeyGen_time1
        result.append(KeyGen_time/iter)

        

        file = open("app/Generic/parameters/Genericsk_{}.txt".format(n_R), "w") 
        str = repr(sk)
        file.write(str)
        file.close()
        result.append(os.path.getsize("app/Generic/parameters/Genericsk_{}.txt".format(n_R))/1000)

        file = open("app/Generic/parameters/Genericpk_{}.txt".format(n_R), "w") 
        str = repr(pk)
        file.write(str)
        file.close()
        result.append(os.path.getsize("app/Generic/parameters/Genericpk_{}.txt".format(n_R))/1000)


        sk_R={};pk_R={}
        (sk_R[0],pk_R[0],LT1) = UPCS.KeyGen(mpk,msk,x)


        # Receivers' key re-randomization
        RandKey_time=0
        for i in range(iter):
            start_bench(groupObj)
            (sk[1],pk[1],LT1) = UPCS.RandKey(mpk,sk[0])
            RandKey_time1, RandKey_pair = end_bench(groupObj)
            RandKey_time += RandKey_time1
        result.append(RandKey_time/iter)

        
        #Sign
        m=group.random()
        Sign_time=0
        for i in range(iter):
            start_bench(groupObj)
            (sigma,LT2) = UPCS.Sign(mpk,sk[1],pk_R[0],m)
            Sign_time1, Sign_pair= end_bench(groupObj)
            Sign_time += Sign_time1
        result.append(Sign_time/iter)


        file = open("app/Generic/parameters/GenericSig_{}.txt".format(n_R), "w")
        file.write(repr(sigma))
        file.close()
        result.append(os.path.getsize("app/Generic/parameters/GenericSig_{}.txt".format(n_R))/1000)
        

        # Verification time
        Verify_time=0
        for i in range(iter):
            start_bench(groupObj)
            out = UPCS.verify(mpk,pk[1],pk_R[0],m,sigma)
            print(out)
            Verify_time1, Verify_pair = end_bench(groupObj)
            Verify_time += Verify_time1
        result.append(Verify_time/iter)
        result.append(Verify_pair)

        # Verification time
        Batched_Verify_time=0
        for i in range(iter):
            start_bench(groupObj)
            out = UPCS.Batched_verify(mpk,pk[1],pk_R[0],m,sigma)
            print(out)
            v_time, Batched_verify_pair = end_bench(groupObj)
            Batched_Verify_time += v_time
        result.append(Batched_Verify_time/iter)
        result.append(Batched_verify_pair)
        return result

book = Workbook()
data = book.active
title = ["N","#att","Setup_time", "msk_size", "mpk_size", "KeyGen_time" ,"sk_size",\
    "pk_size", "RandKey_time", "Sign_time", "sig_size" ,"Verify_time", "Verify_pair",\
        "Batched_Verify_time", "Batched_Verify_pair"]
data.append(title)
Full_benchmark=Full_benchmark(groupObj)

for n_R in range(int(sys.argv[1]),int(sys.argv[2])+1,int(sys.argv[3])): #Use can change this range
    data.append(Full_benchmark.main(n_R,4*n_R+2,int(sys.argv[4])))
    print(n_R,"\n")
book.save("Generic.xlsx")