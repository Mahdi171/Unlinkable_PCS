from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from charm.core.engine.util import objectToBytes
from Acc import ACC
from SPSEQ import SPSEQ as SEQ
from BLS import BLS01 as DS
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com

groupObj = PairingGroup('BN254')
class UPCS():
    def __init__(self, groupObj):
        global util, group     
        group = groupObj
        self.ACC = ACC(groupObj)
        self.SEQ = SEQ(groupObj)
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.Policy = Policy()
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma= Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
    def matching(self,lst):
            indices_dict = {}
            for i, element in enumerate(lst):
                if element in indices_dict:
                    indices_dict[element].append(i)
                else:
                    indices_dict[element] = [i]
            # Filter the dictionary to include only elements with multiple occurrences
            repeated_elements = [indices for element, indices in indices_dict.items() if len(indices) > 1]
            return repeated_elements              
    def Setup(self,F):
        A = {}; alpha={}; W={}; Gamma1={}; Gamma2={}
        pp = BG.Gen(self)
        CRS1, tpd1 = NIZK.Transpatent_Setup(self,pp)
        CRS2, tpd2 = NIZK.Transpatent_Setup(self,pp)
        pp_com = Com.Setup(self)
        (sk_sigA,vk_sigA) = SPS.keygen(self,pp,3)
        (sk_seqA,vk_seqA) = SEQ.keygen(self,pp,3)
        for y in range(len(F)):
            S={}
            (A[y],alpha[y]) = ACC.Create(self,pp)
            S[y]=[x for x in range(len(F)) if F[x,y]==1 and x!=y]
            for i in S[y]:
                w_i = ACC.Add(self,pp,A[y],alpha[y],i)
                W[y,i] = w_i
        msk={'sk_sigA':sk_sigA, 'sk_seqA':sk_seqA, 'A': A, 'W':W}
        mpk={'pp':pp, 'CRS1':CRS1, 'CRS2':CRS2, 'vk_sigA':vk_sigA,\
              'vk_seqA':vk_seqA, 'pp_com':pp_com}
        return (msk, mpk)

    def KeyGen(self,mpk,msk,x):
        W={}
        (A_sd,alpha_sd) = ACC.Create(self,mpk['pp'])
        seed = group.random()
        w_sd = ACC.Add(self,mpk['pp'],A_sd,alpha_sd,seed)
        M = [A_sd,msk['A'][x],mpk['pp']['G2']]
        sigma_SEQ = SEQ.sign(self,mpk['pp'],msk['sk_seqA'],M)
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        sigma_sig1 = SPS.sign(self,mpk['pp'],msk['sk_sigA'],[mpk['pp']['G1']**seed, vk_sig])
        sigma_sig2 = SPS.sign(self,mpk['pp'],msk['sk_sigA'],[mpk['pp']['G1']**seed, mpk['pp']['G1']**x])
        for index,w in msk['W'].items():
            if index[1] == x:
                W[index[0]] = [w,SPS.sign(self,mpk['pp'],msk['sk_sigA'],[mpk['pp']['G1']**seed,w])]
        usk={'M':M,'sigma_SEQ':sigma_SEQ,'W':W,'w_sd':w_sd,'seed':seed,\
             'sk_sig':sk_sig,'vk_sig':vk_sig,'sigma_sig1':sigma_sig1, 'sigma_sig2':sigma_sig2,'x':x}
        sk=[usk,-1,"perp"]
        return UPCS.RandKey(self,mpk,sk)
    



    def RandKey(self,mpk,sk):
        GS_proof={}; GS_comX={}; GS_comY={}; pp=mpk['pp']
        GS_X = []; GS_Y = []; GS_Ca=[]; GS_Cb=[]; Gamma={}
        X_Bridge = {}; Pi_Bridge = {}
        
        mu = group.random()
        (M_P,Sigma_P) = SEQ.ChgRep(self,mpk['pp'],sk[0]['M'],sk[0]['sigma_SEQ'],mu)
        
        # --> L1.1: The knowledge of a witness for the Accumulator
        x = [pp['G1'], sk[0]['w_sd'], sk[0]['w_sd']]
        y = [M_P[2], M_P[0], M_P[2]**sk[0]['seed']]
        c_a = [pp['G1'], None, None]
        c_b = [M_P[2], M_P[0], None]
        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
        Gamma[1] = [[-1,0,0],[0,1,0],[0,0,1]]
        indices_dict_x = [1, 2, 2]; indices_dict_y = [1,2,3,3]
        
        # --> L1.2: PRF evaluation and its proof
        pp = mpk['pp']; pp_com = mpk['pp_com']; X=sk[1]+1
        ID = PRF.Gen(self.PRF,pp_com,sk[0]['seed'],X)
        e1, e2, e3 = group.random(), group.random(), group.random()
        cm1 = Com.com(self.Com,pp_com,X,e1)
        cm2 = Com.com(self.Com,pp_com,sk[0]['seed'],e2)
        cm3 = Com.com(self.Com,pp_com,X+sk[0]['seed'],e3)
        w = (X,sk[0]['seed'],e1,e2,e3)
        x = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma,x,w)
        
        # --> Bridge2: ctr
        gamma = group.random()
        com_aux = Com.com(self,pp_com,X,gamma)
        w = (X,e1,gamma,0,0)
        x = (cm1, com_aux, pp_com['G'], pp_com['H'], group.init(G1,1),\
              pp_com['G'], pp_com['H'], group.init(G1,1))
        pi = Sigma.D_Bridging.Prove(self.Sigma,x,w)
        X_Bridge[1] = x; Pi_Bridge[1] = pi

        # --> L1.3: Range_proof for the counter X
        (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V) = RangeProof.Setup(self.RangeProof,2 ** 16 - 1, 16)
        proof = RangeProof.RanProve(self.RangeProof,v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp = (V, g, h, gs, hs, u, proof,seeds)
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        sigma_sig = DS.sign(self,mpk['pp'],sk[0]['sk_sig'],[ID,vk_sig])

        # --> L1.4: SPS verifrication
            # first equation
        x = [pp['G1']**sk[0]['seed'], sk[0]['vk_sig'],sk[0]['sigma_sig1']['R']]
        y = [mpk['vk_sigA'][0],mpk['vk_sigA'][1],sk[0]['sigma_sig1']['T']]
        c_a = [None, None, None]
        c_b = [mpk['vk_seqA'][0], mpk['vk_seqA'][1], None]
        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
        Gamma[2] = [[1,0,0],[0,1,0],[0,0,-1]]
            # Second equation
        x = [sk[0]['sigma_sig1']['S'], pp['G1']]
        y = [pp['G2'], sk[0]['sigma_sig1']['T']]
        c_a = [None, pp['G1']]
        c_b = [pp['G2'], None]
        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
        Gamma[3] = [[1,0],[0,-1]]

        # --> L1.5: BLS signature verifrication
        x = [sk[0]['vk_sig'],pp['G1']]
        y = [group.hash(objectToBytes([ID,vk_sig], group), G2), sigma_sig]
        c_a = [None , pp['G1']]
        c_b = [group.hash(objectToBytes([ID,vk_sig], group)), None]
        Gamma[4]=[[1,0],[0,-1]]
        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
        
        # Gamma matrices
        n1 = len(Gamma[1]); n2 = len(Gamma[2]); n3 = len(Gamma[3]); n4 = len(Gamma[4])
        n_cols = len(Gamma[1][0]) + len(Gamma[2][0]) + len(Gamma[3][0]) + len(Gamma[4][0])
        GammaT = [[row + [0]*(n_cols-n1) for row in Gamma[1]],
                [[0]*n1 + row + [0]*(n_cols-n1-n2) for row in Gamma[2]],
                [[0]*(n1+n2) + row + [0]*(n_cols-(n1+n2+n3)) for row in Gamma[3]],
                [[0]*(n1+n2+n3) + row for row in Gamma[4]]]
        GammaT[0].extend([[0]*n_cols]*(n_cols - n1))
        aux1 = [[0]*n_cols]*n1
        aux1.extend(GammaT[1]); aux1.extend([[0]*n_cols]*(n_cols - n1 - n2))
        GammaT[1] = aux1
        aux2= [[0]*n_cols]*(n1+n2)
        aux2.extend(GammaT[2]); aux2.extend([[0]*n_cols]*(n_cols - n1 - n2 - n3))
        GammaT[2] = aux2
        aux3 = [[0]*n_cols]*(n_cols - n4)
        aux3.extend(GammaT[3])
        GammaT[3] = aux3

        ind_x, ind_y = UPCS.matching(self,GS_X), UPCS.matching(self,GS_Y)
        GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK,mpk['CRS1'],GS_X,GS_Y,GS_Ca,GS_Cb,ind_x,ind_y)
        GS_proof = NIZK.prove(self.NIZK,mpk['CRS1'],GS_X,GS_Y,r,s,GS_comY,GammaT)

        # --> Bridge1: k 
        w = (sk[0]['seed'],e2,s[2][0],group.init(ZR,0),s[2][1])
        x = (cm2, GS_comY[2][1], pp_com['G'], pp_com['H'], group.init(G1,1),\
             M_P[2], mpk['CRS1']['vv2'][1], mpk['CRS1']['ww2'][1])
        pi = Sigma.D_Bridging.Prove(self.Sigma,x,w)
        X_Bridge[1] = x; Pi_Bridge[1] = pi

        sigma_sig = DS.sign(self,mpk['pp'],sk[0]['sk_sig'],[ID,vk_sig])
        sk[1] += 1; sk[2] = sk_sig
        pk = {'ID':ID,'vk_sig':vk_sig,'M':M_P,'sigma_SEQ':Sigma_P,'comX':GS_comX,\
            'comY':GS_comY, 'pi':GS_proof, 'rp':rp, 'x_prf':x_prf, 'pi_prf':pi_prf,
            'X_Bridge':X_Bridge,'Pi_Bridge':Pi_Bridge}
        LT1 = {'Gamma':GammaT, 'ind_x':ind_x, 'ind_y':ind_y}
        return sk, pk, LT1

    def Sign(self,mpk,sk,pk_R,m,x,LT1):
        GS_proof = {}; GS_comX = {}; GS_comY = {}; pp_com = mpk['pp_com']
        GS_X = []; GS_Y = []; GS_Ca=[]; GS_Cb=[]; Gamma={}
        X_Bridge = {}; Pi_Bridge = {}
        pp = mpk['pp']; (V, g, h, gs, hs, u, proof,seeds) = pk_R['rp']
        pp_p = {'G1':mpk['pp']['G1'],'G2':pk_R['M'][2],'GT':pair(mpk['pp']['G1'],pk_R['M'][2])}
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M']) and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY'],LT1) and \
            RangeProof.RanVerify(self.RangeProof,V, g, h, gs, hs, u, proof,seeds) and \
                    Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf']) and \
                        Sigma.D_Bridging.Verify(self.Sigma,pk_R['X_Bridge'],pk_R['Pi_Bridge']):
            print("The receiver's public key is valid.\n")
            
            # --> L2.1: PRF evaluation and its proof
            ID = PRF.Gen(self,mpk['pp_com'],sk[0]['seed'],sk[1])
            e1, e2, e3 =group.random(), group.random(), group.random()
            cm1 = Com.com(self,pp_com,sk[1],e1)
            cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
            cm3 = Com.com(self,pp_com,sk[1]+sk[0]['seed'],e3)
            w = (sk[1],sk[0]['seed'],e1,e2,e3)
            ins = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
            x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma,ins,w)
            
            search=0
            while search==0:
                for key, value in sk[0]['W'].items():
                    if ACC.MemVrf(self,pp_p,pk_R['M'][1],x,value[0])==True:
                    
                        # --> L2.2: SPS proof [mpk['pp']['G1']**seed, vk_sig, mpk['pp']['G1']**x]
                            # First equation
                        x = [pp['G1']**sk[0]['seed'], pp['G1']**sk[0]['x'], sk[0]['sigma_sig2']['R']]
                        y = [mpk['vk_sigA'][0],mpk['vk_sigA'][1],sk[0]['sigma_sig2']['T']]
                        c_a = [None, None, None]
                        c_b = [mpk['vk_seqA'][0], mpk['vk_seqA'][1], None]
                        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
                        Gamma[1] = [[1,0,0],[0,1,0],[0,0,-1]]
                            # Second equation
                        x = [sk[0]['sigma_sig2']['S'],pp['G1']]
                        y = [pp['G2'], sk[0]['sigma_sig2']['T']]
                        c_a = [None, pp['G1']]
                        c_b = [pp['G2'], None]
                        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
                        Gamma[2] = [[1,0],[0,-1]]

                        # --> L2.3: The knowledge of a witness for the Accumulator
                        x = [pp['G1'], value[0], value[0]]
                        y = [pk_R['M'][2], pk_R['M'][1], pk_R['M'][2]**sk[0]['x']]
                        c_a = [pp['G1'], None, None]
                        c_b = [pk_R['M'][2], pk_R['M'][0], None]
                        GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
                        Gamma[3] = [[-1,0,0],[0,1,0],[0,0,1]]

                        # Gamma matrices
                        n1 = len(Gamma[1]); n2 = len(Gamma[2]); n3 = len(Gamma[3])
                        n_cols = len(Gamma[1][0]) + len(Gamma[2][0]) + len(Gamma[3][0])
                        GammaT = [[row + [0]*(n_cols-n1) for row in Gamma[1]],
                                [[0]*n1 + row + [0]*(n_cols-n1-n2) for row in Gamma[2]],
                                [[0]*(n1+n2) + row for row in Gamma[3]]]
                        GammaT[0].extend([[0]*n_cols]*(n_cols - n1))
                        aux1 = [[0]*n_cols]*n1
                        aux1.extend(GammaT[1]); aux1.extend([[0]*n_cols]*(n_cols - n1 - n2))
                        GammaT[1] = aux1
                        aux3 = [[0]*n_cols]*(n_cols - n3)
                        aux3.extend(GammaT[2])
                        GammaT[2] = aux3

                        ind_x, ind_y = UPCS.matching(self,GS_X), UPCS.matching(self,GS_Y)
                        GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK,mpk['CRS2'],GS_X,GS_Y,GS_Ca,GS_Cb,ind_x,ind_y)
                        GS_proof = NIZK.prove(self.NIZK,mpk['CRS2'],GS_X,GS_Y,r,s,GS_comY,GammaT)
                        
                        # --> Bridge1: k 
                        w = (sk[0]['seed'],e2,r[0][0],group.init(ZR,0),r[0][1])
                        x = (cm2, GS_comX[0][1], pp_com['G'], pp_com['H'], group.init(G1,1),\
                            pp['G1'], mpk['CRS2']['vv1'][1], mpk['CRS2']['ww1'][1])
                        pi = Sigma.D_Bridging.Prove(self.Sigma,x,w)
                        X_Bridge[1] = x; Pi_Bridge[1] = pi
                        search = 1
            sigma = DS.sign(self,mpk['pp'],sk[2],[m,pk_R['ID']])
            pi={'pi':GS_proof, 'comX':GS_comX, 'comY':GS_comY,'x_prf':x_prf, \
                'pi_prf':pi_prf,'X_Bridge':X_Bridge, 'Pi_Bridge':Pi_Bridge}
            LT2 = {'Gamma':GammaT, "ind_x":ind_x, "ind_y":ind_y}
        return {'sigma':sigma,'pi':pi}, LT2

    def verify(self,mpk,pk_S,pk_R,m,sigma,LT1,LT2):
        pi_s=sigma['pi']; pp=mpk['pp']
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_S['sigma_SEQ'],pk_S['M']) and \
            SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M']) and \
                NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY'],LT1) and \
                NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY'],LT1) and \
                Sigma.PRFprove.Verify(self.Sigma,pi_s['x_prf'],pi_s['pi_prf']) and \
                    Sigma.D_Bridging.Verify(self.Sigma,pk_R['X_Bridge'],pk_R['Pi_Bridge']) and \
                        Sigma.D_Bridging.Verify(self.Sigma,pk_S['X_Bridge'],pk_S['Pi_Bridge']):
            return DS.verify(self,mpk['pp'],pk_S['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                 NIZK.verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY'],LT2) and \
                 Sigma.D_Bridging.Verify(self.Sigma,pi_s['X_Bridge'],pi_s['Pi_Bridge'])
    
    def Batched_verify(self,mpk,pk_S,pk_R,m,sigma,LT1,LT2):
        pi_s = sigma['pi']; pp = mpk['pp']
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_S['sigma_SEQ'],pk_S['M']) and \
            SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M']) and \
                NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY'],LT1) and \
                NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY'],LT1) and \
                Sigma.PRFprove.Verify(self.Sigma,pi_s['x_prf'],pi_s['pi_prf']) and \
                    Sigma.D_Bridging.Verify(self.Sigma,pk_R['X_Bridge'],pk_R['Pi_Bridge']) and \
                    Sigma.D_Bridging.Verify(self.Sigma,pk_S['X_Bridge'],pk_S['Pi_Bridge']):
            return DS.verify(self,mpk['pp'],pk_S['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                 NIZK.Batched_verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY'],LT2) and \
                 Sigma.D_Bridging.Verify(self.Sigma,pi_s['X_Bridge'],pi_s['Pi_Bridge'])
