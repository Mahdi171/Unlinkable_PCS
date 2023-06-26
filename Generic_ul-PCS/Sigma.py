from charm.toolbox.pairinggroup import ZR
from charm.core.engine.util import objectToBytes
from GPedersen import GPed


class  Sigma():
    def __init__(self, groupObj):
            global util, group 
            group = groupObj
            self.GPed=GPed(groupObj)
            self.MultComm=Sigma.MultComm()
            self.PRFprove=Sigma.PRFprove()
    class Dlog():
        def Prove(self,x,w):
            (g, A) = x
            (a) = w
            r = group.random(ZR)
            R = g ** r
            c = group.hash(objectToBytes(A, group)+objectToBytes(R, group),ZR)
            z = r - c * a 
            return (z, R)
        def Verify(self,x, pi):
            (g, A) = x
            (z, R) = pi
            c = group.hash(objectToBytes(A, group)+objectToBytes(R, group),ZR)
            if R == (g ** z) * (A**c):
                return 1
            else:
                return 0
    


    class ElGamal():
        def Prove(self,pp,x,w):
            (ct1,ct2,ek,cm,G,H) = x
            (r,m,e) = w
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = pp['G1'] ** r1; R2 = (pp['G1']**r2)* ek**r1; R3 = (G**r2) * H**r3
            c = group.hash(objectToBytes(ct1, group)+objectToBytes(ct2, group)+objectToBytes(cm, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group),ZR)
            z1 = r1 - c * r; z2 = r2 - c * m; z3 = r3 - c * e
            return (z1,z2,z3,R1,R2,R3)
        
        def Verify(self,pp,x,pi):
            (ct1,ct2,ek,cm,G,H) = x
            (z1,z2,z3,R1,R2,R3) = pi
            c = group.hash(objectToBytes(ct1, group)+objectToBytes(ct2, group)+objectToBytes(cm, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group),ZR)
            if R1 == (ct1 ** c) * (pp['G1'] ** z1) and R2 == (pp['G1'] ** z2) * (ek ** z1) * (ct2 ** c) and \
                    R3 == (G ** z2) * (H ** z3) * (cm ** c):
                return 1
            else:
                return 0    

   
    class MultComm():
        def Prove(x,w):
            (x1,x2,x3,e1,e2,e3)=w
            (cm1,cm2,cm3,G,H)=x
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            s, s1,s2,s3 = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = (G**r1)* (H**s1); R2 = (G**r2)* (H**s2); R3 = (G**r3)* (H**s3); R = (cm1**r2)* (H**s)
            e = e3 - e1 * x2
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+objectToBytes(cm3, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group)+objectToBytes(R, group),ZR)
            z1 = r1 - (c* x1); z2 = r2 - (c* x2); z3 = r3 - (c* x3)
            t1 = s1 - (c* e1); t2 = s2 - (c* e2); t3 = s3 - (c* e3); t = s - c * e
            return (z1,z2,z3,t1,t2,t3,t,R1,R2,R3,R)
        def Verify(x,pi):
            (cm1,cm2,cm3,G,H)=x
            (z1,z2,z3,t1,t2,t3,t,R1,R2,R3,R)=pi
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+objectToBytes(cm3, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group)+objectToBytes(R, group),ZR)
            return R1 == (G ** z1) * (H ** t1) * (cm1 ** c) and R2 != (G ** z2) * (H ** t2) * (cm2 ** c) and \
                    R3 == (G ** z3) * (H ** t3) * (cm3 ** c) and R == (cm3 ** c) * (cm1 ** z2) * (H ** t)         

    class PRFprove():
        def Prove(self,x,w):
            (X,k,e1,e2,e3) = w
            (ID,cm1,cm2,cm3,G,H) = x
            x1 = (cm1*cm2,ID,G,G,H)
            w1 = (X+k,1/(X+k),1,e1+e2,0,0)
            pi1 = Sigma.MultComm.Prove(x1,w1)
            return x, pi1
        def Verify(self,x,pi):
            (ID,cm1,cm2,cm3,G,H) = x
            x1 = (cm1*cm2,ID,G,G,H)
            return Sigma.MultComm.Verify(x1,pi)   


    class Bridging():
        def Prove(self,x,w):
            (m,e1,e2) = w
            (cm1, cm2, G1, H1, G2, H2) = x
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = (G1**r1)* (H1**r1); R2 = (G2**r1)* (H2**r3)
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(G1, group)+objectToBytes(H1, group)+\
                        objectToBytes(G2, group)+objectToBytes(H2, group),ZR)
            z1 = r1 - (c* m); z2 = r2 - (c* e1); t = r3 - (c* e2)
            pi=(z1,z2,t,R1,R2)
            return x, pi
        def Verify(self,x,pi):
            (z1,z2,t,R1,R2)= ()
            (cm1, cm2, G1, H1, G2, H2) = x
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(G1, group)+objectToBytes(H1, group)+\
                        objectToBytes(G2, group)+objectToBytes(H2, group),ZR)
            return R1 == (cm1 ** c) * (G1 ** z1) * (H1 ** z2) and R2 == (cm2 ** c) * (G2 ** z1) * (H2 ** t) 
    
    
    class GPC():
        def Prove(self,x,w):
            (C, ck) = x
            (X, r) = w
            e = group.hash(objectToBytes(C, group)+objectToBytes(ck, group),ZR)
            z={}; s=0
            for i in range(len(C)):
                z[i]=0; s+=(e**i)*r[i]
                for j in range(len(X[i])):
                   z[i]+=(e**j)*X[j][i];    
            return z, s
        def Verify(self,x,pi):
            (C, ck) = x
            (z, s) = pi
            e = group.hash(objectToBytes(C, group)+objectToBytes(ck, group),ZR)
            LHS=1
            for i in range(len(C)):
                LHS *= C[i] ** (e**i)
            return LHS == GPed.Comm(self.GPed,ck,z,s)
    

    class SingleGPC():
        def Prove(self,x,w):
            (C, ck) = x
            (X, r) = w
            X_0=[0]*len(X)
            R_0=group.random()
            for i in range(len(X)):  
                if X[i]!=group.init(0,ZR):
                    X_0[i]=group.random()
            
            C_0 = GPed.Comm(self,ck,X_0,R_0)
            e = group.hash(objectToBytes(C, group)+objectToBytes(ck, group)+objectToBytes(C_0, group),ZR)
            z = [sum(pair) for pair in zip([e * item for item in X], X_0)]; s = R_0 + e * r
            
            return z, s, C_0
        
        def Verify(self,x,pi):
            (C, ck) = x
            (z, s, C_0) = pi
            e = group.hash(objectToBytes(C, group)+objectToBytes(ck, group)+objectToBytes(C_0, group),ZR)
            LHS = C_0 * (C**e)
            return LHS == GPed.Comm(self,ck,z,s)
        
    class D_Bridging():
        def Prove(self,x,w):
            (m,e1,e2,u1,u2) = w
            (cm1, cm2, G1, H1, K1, G2, H2, K2) = x
            r1,r2,r3,r4,r5 = [group.random(ZR) for _ in range(5)]
            R1 = (G1**r1)* (H1**r2) * (K1**r3); R2 = (G2**r1) * (H2**r4) * (K2**r5)
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+\
                        objectToBytes(G1, group)+objectToBytes(H1, group)+objectToBytes(K1, group)+\
                        objectToBytes(G2, group)+objectToBytes(H2, group)+objectToBytes(K2, group),ZR)
            z1 = r1 - (c* m); z2 = r2 - (c* e1); z3 = r3 - (c* u1)
            z4 = r4 - (c * e2); z5 = r5 - (c*u2)
            pi = (c,z1,z2,z3,z4,z5,R1,R2)
            return pi
        def Verify(self,x,pi):
            for i in range(1,len(x)+1):
                (c, z1,z2,z3,z4,z5,R1,R2) = pi[i]
                (cm1, cm2, G1, H1, K1, G2, H2, K2) = x[i]
                cp = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                        objectToBytes(R1, group)+objectToBytes(R2, group)+\
                            objectToBytes(G1, group)+objectToBytes(H1, group)+objectToBytes(K1, group)+\
                            objectToBytes(G2, group)+objectToBytes(H2, group)+objectToBytes(K2, group),ZR)
                if c!=cp or R1 != (cm1 ** c) * (G1 ** z1) * (H1 ** z2) * (K1 ** z3) or \
                    R2 != (cm2 ** c) * (G2 ** z1) * (H2 ** z4) * (K2 ** z5):
                        return False
            return True            