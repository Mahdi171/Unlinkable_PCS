from random import random
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from BG import BG
from pprint import pprint
import numpy as np
from matmath import *

#
#group=PairingGroup('BN254')
#BG = BG(group)
#pp=BG.Gen()

class OT():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)        
        group = groupObj

    def G_IPE(self,pp,N):
        xhi=[];BB={}; BBs={}; a={}; astar={}; br={}; bstarr={}
        for i in range(N):
            a[i]=[group.init(G2,0)]*N; astar[i]=[group.init(G1,0)]*N; 
        psi=group.random()
        for i in range(N):
            a[i][i]=pp['G2']; astar[i][i]=pp['G1']
            xhi.append([group.random() for _ in range(N)])
        V = Inverse([*zip(*xhi)])
        for k in range(N):
            br = [group.init(G2,1)]*N; bstarr = [group.init(G1,1)]*N
            for i in range(N):
                for j in range(N):
                    br[i] *= a[i][j] ** xhi[k][j]
                    bstarr[i] *= astar[i][j] ** (psi*V[k][j])
            BB[k]=br; BBs[k]=bstarr
        param={'BB':BB, 'BBs':BBs}
        return param, pp['GT']**psi, pp['G2']**psi

    def Setup(self,param,N):
        #(BB,BBs) = param #Parse
        BBh={}; BBhs={}
        n=int((N-2)/4)
        for i in range(N):
                if 0 <= i <= n or i== 4*n+1:
                    BBh[i] = param['BB'][i]
                if 0 <= i <= n or 3*n+1 <= i <= 4*n:
                    BBhs[i] = param['BBs'][i]
        pk = {'n':n, 'BB': param['BB'], 'BBh':BBh}
        sk = {'BBs': param['BBs'], 'BBhs':BBhs}
        return pk, sk

    def KeyGen(self,pk,sk,v):
        #(n, BB, BBh) = pk #Parse
        #(BBs, BBhs) = sk #Parse*
        ks={}; result = {}; N = 4*pk['n']+2
        ks[0] = group.init(ZR,1)
        sigma = group.random()
        for i in range(1,pk['n']+1): 
            ks[i] = sigma * v[i-1]
        for i in range(pk['n']+1,3*pk['n']+1):
            ks[i] = group.init(ZR,0)
        for i in range(3*pk['n']+1,N-1):
            ks[i] = group.random() #mu
        ks[N-1] = group.init(ZR,0)
        for i in range(N):
            aux = group.init(G1,1)
            for j in range(N):
                aux *= sk['BBs'][j][i] ** ks[j]
            result[i] = aux
        return result

    def Enc(self,pk,x):
        #(n, BB, BBh) = pk #Parse
        omega={}; result={}; c1={}; N=4*pk['n']+2
        c1[0]=group.init(ZR,1)
        omega=group.random()
        for i in range(1,pk['n']+1):
            c1[i] = omega*x[i-1]
        for i in range(pk['n']+1,4*pk['n']+1):
            c1[i] = group.init(ZR,0)
        c1[N-1]=group.random() #phi
        for i in range(N):
            aux = group.init(G2,1)
            for j in range(N):
                aux *= pk['BB'][j][i]**c1[j]
            result[i] = aux
        return result
    
    def Dec(self,pk,sk_v,ct_x):
        #(n, BB, BBh) = pk #Parse
        N = 4*pk['n']+2
        out = group.init(GT,1)
        for i in range(N):
            out *= pair(sk_v[i],ct_x[i])
        return out
#
#
#OT=OT(group)
#N=10
#n=int((N-2)/4)
#param,gT = OT.G_IPE(pp,N)
##(BB, BBs)=param
#pk,sk=OT.Setup(param,N)
#v=[group.random(ZR) for _ in range(n-1)]
#x=[group.random(ZR) for _ in range(n-1)]
#p=group.order()
#v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
#x.append(1)
#prod = np.sum([x * y for x, y in zip(v, x)]) 
#print('IP(x,v)={}'.format(prod))
#sk_v=OT.KeyGen(pk,sk,v)
##x=[group.random(ZR) for _ in range(n)]
#ct_x = OT.Enc(pk,x)
#out=OT.Dec(pk,sk_v,ct_x)
#print(out==gT)
#