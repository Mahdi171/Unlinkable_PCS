
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from charm.toolbox.secretutil import SecretUtil
from BLS import BLS01 as DS
from BG import BG
from OT12 import OT as FE
from SPS import SPS
from GS import GS as NIZK

from openpyxl import Workbook
import os
from charm.core.engine.util import serializeObject
import numpy as np
from main import PCS
import sys

groupObj = PairingGroup('BN254')
DS = DS(groupObj)
BG = BG(groupObj)
NIZK = NIZK(groupObj)
SPS = SPS(groupObj)
PCS = PCS(groupObj)
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
        v=[group.random(ZR) for _ in range(n-1)]
        x=[group.random(ZR) for _ in range(n-1)]
        p=group.order()
        v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
        x.append(1) 
        print('IP(x,v)={}'.format(np.sum([x * y for x, y in zip(v, x)])))

        #CA Key Gen
        setup_time=0
        for _ in range(iter):
            start_bench(groupObj)
            (msk, mpk) = PCS.Setup(N)
            setup_time1, setup_pair= end_bench(groupObj)
            setup_time += setup_time1
        result.append(setup_time/iter)
        
        file = open("/app/PCS/parameters/PCSmsk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(msk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/PCS/parameters/PCSmsk_{}.txt".format(n_R))/1000)


        file = open("/app/PCS/parameters/PCSmpk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(mpk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/PCS/parameters/PCSmpk_{}.txt".format(n_R))/1000)


        KeyGen_time=0
        for i in range(iter):
            start_bench(groupObj)
            (sk,pk) = PCS.KeyGen(mpk,msk,x)
            KeyGen_time1, keygen_pair = end_bench(groupObj)
            KeyGen_time += KeyGen_time1
        result.append(KeyGen_time/iter)
        
        
        file = open("/app/PCS/parameters/PCSsk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(sk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/PCS/parameters/PCSsk_{}.txt".format(n_R))/1000)

        
        
        
        file = open("/app/PCS/parameters/PCSpk_{}.txt".format(n_R), "w") 
        str = repr(serializeObject(pk,group))
        file.write(str)
        file.close()
        result.append(os.path.getsize("/app/PCS/parameters/PCSpk_{}.txt".format(n_R))/1000)

        
        (sk_R,pk_R) = PCS.KeyGen(mpk,msk,v)

        result.append("None")
        #Sign
        m=group.random()
        Sign_time=0
        for i in range(iter):
            start_bench(groupObj)
            sigma,LT = PCS.Sign(mpk,sk,pk_R,m)
            Sign_time1, Sign_pair= end_bench(groupObj)
            Sign_time += Sign_time1
        result.append(Sign_time/iter)
        
        
        file = open("/app/PCS/parameters/PCSSig_{}.txt".format(n_R), "w")
        file.write(repr(sigma))
        file.close()
        result.append(os.path.getsize("/app/PCS/parameters/PCSSig_{}.txt".format(n_R))/1000)

        # Verification time
        Verify_time=0
        for i in range(iter):
            start_bench(groupObj)
            out = PCS.verify(mpk,pk,pk_R,m,sigma,LT)
            print("Non_Batched", out)
            Verify_time1, Verify_pair = end_bench(groupObj)
            Verify_time += Verify_time1
        result.append(Verify_time/iter)
        result.append(Verify_pair)

        # Verification time
        Batched_Verify_time=0
        for i in range(iter):
            start_bench(groupObj)
            out = PCS.Batched_verify(mpk,pk,pk_R,m,sigma,LT)
            print("Bathced", out)
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
book.save("PCS.xlsx")