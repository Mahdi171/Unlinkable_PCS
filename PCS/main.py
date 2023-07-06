from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from BLS import BLS01 as DS
from BG import BG
from SPS import SPS
from GS import GS as NIZK
from OT12 import OT as FE
import numpy as np
groupObj = PairingGroup('BN254')

RUN = True

class PCS():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)        
        group = groupObj
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.NIZK = NIZK(groupObj)
        self.SPS = SPS(groupObj)
        self.FE = FE(groupObj)
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
    def Setup(self,N):
        pp = BG.Gen(self.BG); n = int((N-2)/4)
        CRS, tpd = NIZK.Transpatent_Setup(self.NIZK,pp)
        param, gT, g2 = FE.G_IPE(self.FE,pp,N) #OT12 pre setup
        mpk_fe, msk_fe = FE.Setup(self.FE,param,N) #OT12 main setup
        (sk_pub,vk_pub) = DS.keygen(self.DS,pp)
        (sk_priv,vk_priv) = SPS.keygen(self.SPS,pp,N+1)
        msk={'msk_fe': msk_fe, 'sk_pub':sk_pub,'sk_priv':sk_priv}
        mpk={'pp':pp, 'CRS':CRS, 'vk_pub':vk_pub,'vk_priv':vk_priv, 'mpk_fe':mpk_fe,\
             'g2':g2, 'gT':gT, 'N':N}
        while True:
            v=[group.random() for _ in range(n-1)]
            x=[group.random() for _ in range(n-1)]
            p=group.order()
            v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
            x.append(group.init(ZR,1))
            if group.init(ZR,np.sum([x * y for x, y in zip(v, x)]))==group.init(ZR,0):
                sk,pk = PCS.KeyGen(self,mpk,msk,x)
                sk_R,pk_R = PCS.KeyGen(self,mpk,msk,v)
                sigma, LT = PCS.Sign(self,mpk,sk,pk_R,group.random())
                mpk['LT'] = LT
                break
        return (msk, mpk)

    def KeyGen(self,mpk,msk,x):
        pp = mpk['pp']
        (sk_P,vk_P) = DS.keygen(self.DS,pp)
        ct_fe = FE.Enc(self.FE,mpk['mpk_fe'],x)
        sk_fe = FE.KeyGen(self.FE,mpk['mpk_fe'],msk['msk_fe'],x)
        mes_pub = [vk_P,ct_fe]
        sigma_pub = DS.sign(self.DS, pp,msk['sk_pub'],mes_pub)
        mes_priv = [vk_P]
        for key, value in sk_fe.items():
            mes_priv.append(value)
        sigma_priv = SPS.sign(self.SPS,pp,msk['sk_priv'],mes_priv)
        sk = {'vk_P':vk_P, 'sk_P':sk_P, 'sk_fe':sk_fe, 'sigma_priv':sigma_priv}
        pk = {'vk_P':vk_P, 'ct':ct_fe, 'sigma_pub':sigma_pub}
        return sk,pk


    def Sign(self,mpk,sk,pk_R,M):
        pp = mpk['pp']; GS_X=[]; GS_Y=[]; GS_Ca=[]; GS_Cb=[]; Gamma={}
        N = mpk['N']; Gamma={}; #GS_proof = {}; GS_comX = {}; GS_comY = {};
        if  DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) == 1 and \
            FE.Dec(self.FE,mpk['mpk_fe'],sk['sk_fe'],pk_R['ct']) == mpk['gT']:
            
            # FE.Dec(sk_x,ct_R)=g_T
            x=[]; y=[]
            for i in range(len(sk['sk_fe'])):
                x.append(sk['sk_fe'][i])
                y.append(pk_R['ct'][i])
            c_a = [None]*N
            x.append(pp['G1']); y.append(mpk['g2'])
            Gamma[1]=[]
            for i in range(len(x)):
                if i < len(sk['sk_fe']):
                    aux=[0]*len(y); aux[i]=1
                    Gamma[1].append(aux)
                else:
                    aux=[0]*len(y); aux[i]=-1
                    Gamma[1].append(aux)
            c_a.append(mpk['g2'])
            c_b = y
            GS_X += x; GS_Y += y; GS_Ca += c_a; GS_Cb += c_b
            
            # The SPS of seed and sk_fe
            c_b = []
            x = [sk['vk_P']]; y = [mpk['vk_priv'][0]]
            for i in range(len(sk['sk_fe'])):
                x.append(sk['sk_fe'][i])
                y.append(mpk['vk_priv'][i+1])
            x.extend([sk['sigma_priv']['R']])
            c_b.extend(y)
            c_a = [None]*(N+2)
            y.extend([sk['sigma_priv']['T']])
            c_b.extend([None])
            GS_X += x; GS_Y += y; GS_Ca += c_a; GS_Cb += c_b
            
            
            Gamma[2]=[]
            for i in range(len(x)):
                if i <= len(sk['sk_fe']):
                    aux=[0]*len(y); aux[i]=1
                    Gamma[2].append(aux)
                elif i == len(sk['sk_fe'])+1:
                    aux=[0]*len(y); aux[i]=-1
                    Gamma[2].append(aux)
                elif i == len(sk['sk_fe'])+2:
                    aux=[0]*len(y); aux[i]=1
                    Gamma[2].append(aux)
                else:
                    aux=[0]*len(y); aux[i]=-1
                    Gamma[2].append(aux)
            # Second equation
            x = [sk['sigma_priv']['S'], pp['G1']]
            y = [pp['G2'], sk['sigma_priv']['T']]
            c_a = [None, pp['G1']]
            c_b = [pp['G2'], None]
            GS_X += x; GS_Ca += c_a; GS_Y += y; GS_Cb += c_b
            Gamma[3] = [[1,0],[0,-1]]
            
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

            ind_x, ind_y = PCS.matching(self,GS_X), PCS.matching(self,GS_Y)
            GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK,mpk['CRS'],GS_X,GS_Y,GS_Ca,GS_Cb,ind_x,ind_y)
            GS_proof = NIZK.prove(self.NIZK,mpk['CRS'],GS_X,GS_Y,r,s,GS_comY,GammaT)
            
            sigma = DS.sign(self.DS, pp,sk['sk_P'],[M,pk_R['vk_P']])
            pi = {'pi':GS_proof, 'comX':GS_comX, 'comY':GS_comY}
            LT = {'Gamma':GammaT, 'ind_x':ind_x, 'ind_y':ind_y}
        else:
            print("There is no link")
            sigma="perp"; pi="perp"
        return {'sigma':sigma,'pi':pi}, LT

    def verify(self,mpk,pk_S,pk_R,M,sigma):
        pp = mpk['pp']
        pi_s = sigma['pi']
        return DS.verify(self.DS, pp,pk_S['vk_P'],sigma['sigma'],[M,pk_R['vk_P']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_S['sigma_pub'],[pk_S['vk_P'],pk_S['ct']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) and \
            NIZK.verify(self.NIZK,pp,mpk['CRS'],pi_s['pi'],pi_s['comX'],pi_s['comY'],mpk['LT'])
                
    def Batched_verify(self,mpk,pk_S,pk_R,M,sigma):
        pp = mpk['pp']
        pi_s = sigma['pi']
        return DS.verify(self.DS, pp,pk_S['vk_P'],sigma['sigma'],[M,pk_R['vk_P']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_S['sigma_pub'],[pk_S['vk_P'],pk_S['ct']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS'],pi_s['pi'],pi_s['comX'],pi_s['comY'], mpk['LT'])
