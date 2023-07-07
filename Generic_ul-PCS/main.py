from random import random
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2
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
import numpy as np
#from HVE import HVE08
groupObj = PairingGroup('BN254')

class UPCS():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj
        self.ACC = ACC(groupObj)
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma = Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
        FE.self = FE(groupObj)
        self.SEQ = SEQ(groupObj)
        self.GPed = GPed(groupObj)
    
    def matching(self, lst):
        indices_dict = {}
        for i, element in enumerate(lst):
            if element in indices_dict:
                indices_dict[element].append(i)
            else:
                indices_dict[element] = [i]
        
        # Filter the dictionary to include only elements with multiple occurrences
        repeated_elements = [indices for element, indices in indices_dict.items() if len(indices) > 1]
        return repeated_elements

    def Setup(self, N):
        BB_T = {}
        ck = {}
        n = (N - 2) // 4 
        
        pp = BG.Gen(self.BG)
        h = group.random(G2)
        pp_com = Com.Setup(self.Com)

        CRS1, _ = NIZK.Transpatent_Setup(self.NIZK, pp)
        CRS2, _ = NIZK.Transpatent_Setup(self.NIZK, pp)

        sk_sigA, vk_sigA = SPS.keygen(self.SPS, pp, N + 2)
        sk_seq, vk_seq = SEQ.keygen(self.SEQ, pp, N + 2)  # For POK of FE ciphertext

        param, gT, g2 = FE.G_IPE(FE.self, pp, N)  # OT12 pre setup
        mpk_fe, msk_fe = FE.Setup(FE.self, param, N)  # OT12 main setup

        # Initialize BB_T
        BB_T = {i: [group.init(G2, 1)] * N for i in range(N)}

        # Fill BB_T using mpk_fe
        for i in range(N):
            for j in range(N):
                BB_T[i][j] = mpk_fe['BB'][j][i]

        # Initialize ck
        for i in range(N):
            ck[i]=[h]; ck[i].extend(BB_T[i])

        msk = {'sk_sigA': sk_sigA, 'msk_fe': msk_fe, 'sk_seq': sk_seq}
        mpk = {
            'pp': pp, 'pp_com': pp_com, 'CRS1': CRS1, 'CRS2': CRS2, 'vk_sigA': vk_sigA,
            'vk_seq': vk_seq, 'mpk_fe': mpk_fe, 'gT': gT, 'N': N, 'ck': ck, 'h': h, 'g2': g2
        }

        # In order to obtain the lookup tables LT1 and LT2,
        # the authority runs KeyGen and signing algorithms for a pair of keys that fulfill the policy
        while True:
            v = [group.random() for _ in range(n - 1)]
            x = [group.random() for _ in range(n - 1)]
            p = group.order()
            v.append(p - sum(xi * yi for xi, yi in zip(v, x)))
            x.append(group.init(ZR, 1))

            if group.init(ZR,sum(xi * yi for xi, yi in zip(v, x))) == group.init(ZR, 0):
                sk, _, LT1 = UPCS.KeyGen(self, mpk, msk, x)
                _, pk_R, LT1 = UPCS.KeyGen(self, mpk, msk, v)
                mpk['LT1'] = LT1
                _, LT2 = UPCS.Sign(self, mpk, sk, pk_R, groupObj.random())
                mpk['LT2'] = LT2
                break

        return msk, mpk


    def KeyGen(self, mpk, msk, x):
        seed = group.random()
        pp = mpk['pp']
        A_sd, alpha_sd = ACC.Create(self.ACC, pp)
        w_sd = ACC.Add(self.ACC, pp, A_sd, alpha_sd, seed)

        sk_sig, vk_sig = DS.keygen(self.DS, pp)
        aux1 = [pp['G1'] ** seed]; aux1.extend([pp['G1'] ** val for val in x])
        sk_fe = FE.KeyGen(FE.self, mpk['mpk_fe'], msk['msk_fe'], x)
        aux2 = [pp['G1'] ** seed, vk_sig]
        aux3 = [pp['G1'] ** seed]
        for i in range(len(sk_fe)):
            aux3.append(sk_fe[i])

        sigma_sig1 = SPS.sign(self.SPS, pp, msk['sk_sigA'], aux1)
        sigma_sig2 = SPS.sign(self.SPS, pp, msk['sk_sigA'], aux2)
        sigma_sig3 = SPS.sign(self.SPS, pp, msk['sk_sigA'], aux3)

        n = len(x)
        N = 4 * n + 2
        C = {}
        Phi = {}
        r_C = {}
        r_Phi = {}
        vec = [group.init(ZR,0)]
        vec.extend(x)
        vec.extend([group.init(ZR,0)]*(3*n+1))
        phi = [group.init(ZR,0)]*N
        phi[0] = 1
        phi[n + 1] = group.random()
        phi[N - 1] = group.random()

        for j in range(N):
            r_C[j] = group.random()
            C[j] = GPed.Com(self.GPed, mpk['ck'][j], vec, r_C[j])
            r_Phi[j] = group.random()
            Phi[j] = GPed.Com(self.GPed, mpk['ck'][j], phi, r_Phi[j])

        C_sign = [A_sd, pp['G2']]
        for i in range(len(C)):
            C_sign.append(C[i])
        sigma_FE = SEQ.sign(self.SEQ, pp, msk['sk_seq'], C_sign)

        usk = {
            'seed': seed, 'sk_sig': sk_sig, 'vk_sig': vk_sig, 'sk_fe': sk_fe,
            'sigma_sig1': sigma_sig1, 'sigma_sig2': sigma_sig2, 'sigma_sig3': sigma_sig3,
            'x': x, 'w_sd': w_sd
        }
        ct_proof = {
            'C': C, 'C_sign': C_sign, 'sigma_FE': sigma_FE, 'r_C': r_C,
            'r_phi': r_Phi, 'phi': phi, 'Phi': Phi
        }
        sk = [usk, -1, "perp", ct_proof]

        return UPCS.RandKey(self, mpk, sk)

        

    def RandKey(self, mpk, sk):
        pp = mpk['pp']
        pp_com = mpk['pp_com']
        X = sk[1] + 1
        GS_X = []
        GS_Y = []
        GS_Ca = []
        GS_Cb = []
        Gamma = {}
        Final = {}
        c_x = {}
        R = {}
        c_a = []
        c_b = []
        X_Bridge = {}
        Pi_Bridge = {}

        # --> L_1.1: PRF and its proof
        ID = PRF.Gen(self.PRF, pp, sk[0]['seed'], sk[1] + 1)
        e1, e2, e3 = group.random(), group.random(), group.random()
        cm1 = Com.com(self.Com, pp_com, X, e1)
        cm2 = Com.com(self.Com, pp_com, sk[0]['seed'], e2)
        cm3 = Com.com(self.Com, pp_com, X + sk[0]['seed'], e3)
        w = (X, sk[0]['seed'], e1, e2, e3)
        x = (ID, cm1, cm2, cm3, pp_com['G'], pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma, x, w)

        # --> L_1.2: range_proof
        v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V = RangeProof.Setup(self.RangeProof, X, 16)
        proof = RangeProof.RanProve(self.RangeProof, v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp = (V, g, h, gs, hs, u, proof, seeds)

        # --> Bridge_1:ctr
        gamma = group.random()
        com_aux = Com.com(self, pp_com, X, gamma)
        w = (X, e1, gamma, 0, 0)
        x = (cm1, com_aux, pp_com['G'], pp_com['H'], group.init(G1, 1),
            pp_com['G'], pp_com['H'], group.init(G1, 1))
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[1] = x
        Pi_Bridge[1] = pi

        # --> SPS, \sigma_2
        gamma1 = []
        x = [pp['G1'] ** sk[0]['seed']]
        for i in range(len(sk[0]['x'])):
            x.append(pp['G1']**sk[0]['x'][i])
        x.extend([sk[0]['sigma_sig1']['R']])
        c_a.extend(["None"] * len(x))
        y = []
        for j in range(len(x)-1):
            y.append(mpk['vk_sigA'][j])
        c_b.extend(y)
        y.extend([sk[0]['sigma_sig1']['T']])
        c_b.append("None")

        for j in range(len(x)):
            if j <= len(sk[0]['x']):
                aux = [0] * len(y)
                aux[j] = 1
                gamma1.append(aux)
            if j == len(sk[0]['x']) + 1:
                aux = [0] * len(y)
                aux[j] = -1
                gamma1.append(aux)

        Gamma[1] = gamma1
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b

        # Second equation
        x = [sk[0]['sigma_sig1']['S'], pp['G1']]
        y = [pp['G2'], sk[0]['sigma_sig1']['T']]
        c_a = ["None", pp['G1']]
        c_b = [pp['G2'], "None"]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b
        Gamma[2] = [[1, 0], [0, -1]]

        # --> L_1.4: Proof of knowledge of encryption
        n = len(sk[0]['x'])
        N = 4 * n + 2
        vec = {}
        x_fe = {}
        pi_fe = {}
        for i in range(N):
            x_fe[i] = (sk[3]['Phi'][i], mpk['ck'][i])
            w_fe = (sk[3]['phi'], sk[3]['r_phi'][i])
            pi_fe[i] = Sigma.SingleGPC.Prove(self.Sigma, x_fe[i], w_fe)

        omega = group.random()
        Final = {}
        c_x = {}
        R = {}
        C_P, sigma_P = SEQ.ChgRep(self.SEQ, pp, sk[3]['C_sign'], sk[3]['sigma_FE'], omega)

        for j in range(N):
            vec[j] = [0]
            vec[j].extend(sk[0]['x'])
            vec[j].extend([0] * (3 * n + 1))
        for i in range(N):
            c_x[i] = sk[3]['phi'][i] + (vec[0][i] * omega)
            Final[i] = sk[3]['Phi'][i] * C_P[i + 2]
            R[i] = omega * sk[3]['r_C'][i] + sk[3]['r_phi'][i]

        x = [pp['G1'], sk[0]['w_sd'], sk[0]['w_sd']]
        y = [C_P[1], C_P[0], C_P[1] ** sk[0]['seed']]
        c_a = [pp['G1'], None, None]
        c_b = [C_P[1], C_P[0], None]
        Gamma[3] = [[-1, 0, 0], [0, 1, 0], [0, 0, 1]]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b

        # --> L_1.5 & L_1.6: SPS and BLS Signature proof
        # --> L_1.5: SPS signature
        x = [pp['G1'] ** sk[0]['seed'], sk[0]['vk_sig'], sk[0]['sigma_sig2']['R']]
        c_a = ["None"] * 3
        y = [mpk['vk_sigA'][0], mpk['vk_sigA'][1], sk[0]['sigma_sig2']['T']]
        c_b = y + ["None"]
        Gamma[4] = [[1, 0, 0], [0, 1, 0], [0, 0, -1]]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b


        # Second equation
        x = [sk[0]['sigma_sig2']['S'], pp['G1']]
        c_a = ["None", pp['G1']]
        y = [pp['G2'], sk[0]['sigma_sig2']['T']]
        c_b = [pp['G2'], "None"]
        Gamma[5] = [[1, 0], [0, -1]]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b

        # L1.6: BLS signature
        (sk_sig, vk_sig) = DS.keygen(self.DS, pp)
        sigma_ctr = DS.sign(self.DS, pp, sk[0]['sk_sig'], [ID, vk_sig])
        x = [sk[0]['vk_sig'], pp['G1']]
        y = [group.hash(objectToBytes([ID, vk_sig], group), G2), sigma_ctr]
        c_a = [None, pp['G1']]
        c_b = [group.hash(objectToBytes([ID, vk_sig], group), G2), None]
        Gamma[6] = [[1, 0], [0, -1]]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b

        # Gamma matrices
        n1 = len(Gamma[1]); n2 = len(Gamma[2]); n3 = len(Gamma[3])
        n4 = len(Gamma[4]); n5 = len(Gamma[5]); n6 = len(Gamma[6])
        n_cols = 0
        for i in range(1,7):
            n_cols += len(Gamma[i][0])
        GammaT = [[row + [0]*(n_cols-n1) for row in Gamma[1]],
                [[0]*n1 + row + [0]*(n_cols-n1-n2) for row in Gamma[2]],
                [[0]*(n1+n2) + row + [0]*(n_cols-(n1+n2+n3)) for row in Gamma[3]],
                [[0]*(n1+n2+n3) + row + [0]*(n5+n6) for row in Gamma[4]],
                [[0]*(n1+n2+n3+n4) + row + [0]*(n6) for row in Gamma[5]],
                [[0]*(n_cols-n6) + row for row in Gamma[6]]]
        GammaT[0].extend([[0]*n_cols]*(n_cols - n1))
        aux1 = [[0]*n_cols]*n1
        aux1.extend(GammaT[1]); aux1.extend([[0]*n_cols]*(n_cols - n1 - n2))
        GammaT[1] = aux1
        aux2 = [[0]*n_cols]*(n1+n2)
        aux2.extend(GammaT[2]); aux2.extend([[0]*n_cols]*(n4+n5+n6))
        GammaT[2] = aux2
        aux3 = [[0]*n_cols]*(n1+n2+n3)
        aux3.extend(GammaT[3]); aux3.extend([[0]*n_cols]*(n5+n6))
        GammaT[3] = aux3
        aux4 = [[0]*n_cols]*(n1+n2+n3+n4)
        aux4.extend(GammaT[4]); aux4.extend([[0]*n_cols]*(n6))
        GammaT[4] = aux4
        aux5 = [[0]*n_cols]*(n_cols - n6)
        aux5.extend(GammaT[5])
        GammaT[5] = aux5

        ind_x = UPCS.matching(self, GS_X)
        ind_y = UPCS.matching(self, GS_Y)

        GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK, mpk['CRS1'], GS_X, GS_Y, GS_Ca, GS_Cb, ind_x, ind_y)
        GS_proof = NIZK.prove(self.NIZK, mpk['CRS1'], GS_X, GS_Y, r, s, GS_comY, GammaT)

        # Bridge2: k & SPS sigma^1
        w = (sk[0]['seed'], e2, r[0][0], group.init(ZR, 0), r[0][1])
        x = (cm2, GS_comX[0][1], pp_com['G'], pp_com['H'], group.init(G1, 1), pp['G1'],
            mpk['CRS1']['vv1'][1], mpk['CRS1']['ww1'][1])
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[2] = x
        Pi_Bridge[2] = pi

        # Bridge3: k & Acc
        idx = GS_Y.index(C_P[1] ** sk[0]['seed'])
        w = (sk[0]['seed'], e2, s[idx][0], group.init(ZR, 0), s[idx][1])
        x = (cm2, GS_comY[idx][1], pp_com['G'], pp_com['H'], group.init(G1, 1), C_P[1],
            mpk['CRS1']['vv2'][1], mpk['CRS1']['ww2'][1])
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[3] = x
        Pi_Bridge[3] = pi

        # Bridge4: k & SPS sigma^2
        idx = GS_Y.index(C_P[1] ** sk[0]['seed'])
        w = (sk[0]['seed'], e2, r[idx + 1][0], group.init(ZR, 0), r[idx + 1][1])
        x = (cm2, GS_comX[idx + 1][1], pp_com['G'], pp_com['H'], group.init(G1, 1),
            pp['G1'], mpk['CRS1']['vv1'][1], mpk['CRS1']['ww1'][1])
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[4] = x
        Pi_Bridge[4] = pi

        sk[1] += 1
        sk[2] = sk_sig

        LT1 = {'Gamma': GammaT, 'ind_x': ind_x, 'ind_y': ind_y}
        pk = {
            'ID': ID, 'vk_sig': vk_sig, 'ct': Final, 'comX': GS_comX, 'comY': GS_comY,
            'pi': GS_proof, 'rp': rp, 'x_prf': x_prf, 'pi_prf': pi_prf,
            'sigma_P': sigma_P, 'Phi': sk[3]['Phi'], 'pi_fe': pi_fe, 'R': R, 'C_P': C_P,
            'X_Bridge': X_Bridge, 'Pi_Bridge': Pi_Bridge
        }

        return sk, pk, LT1





    def Sign(self, mpk, sk, pk_R, mes):
        pp = mpk['pp']
        V, g, h, gs, hs, u, proof, seeds = pk_R['rp']
        X = sk[1] + 1
        pp_com = mpk['pp_com']
        GS_proof = {}
        GS_comX = {}
        GS_comY = {}
        N = mpk['N']
        n = (N - 2) // 4
        Gamma = {}
        ct_fe = {}
        z = {}
        C_P = []
        GS_X = []
        GS_Y = []
        GS_Ca = []
        GS_Cb = []
        X_Bridge = {}
        Pi_Bridge = {}

        for i in range(N):
            ct_fe[i] = ((mpk['h'] ** (-pk_R['R'][i])) * pk_R['ct'][i])

        # To verify the knowledge of openings of GPC
        x_fe = {}
        for j in range(N):
            x_fe[j] = (pk_R['Phi'][j], mpk['ck'][j])

        result_fe = [1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma, x_fe[j], pk_R['pi_fe'][j])]

        result_z = True

        # To check the Zero positions in vector phi
        for j in range(N):
            z[j], s, C_0 = pk_R['pi_fe'][j]
            C_P.append(pk_R['ct'][j] / pk_R['Phi'][j])
            for i in [x for x in range(N) if x != 0 and x != n + 1 and x != N - 1]:
                if z[j][i] != group.init(0, ZR):
                    result_z = False

        result_CP = [1 for j in range(N) if C_P[j] == pk_R['C_P'][j + 2]]

        if (
            FE.Dec(FE.self, mpk['mpk_fe'], sk[0]['sk_fe'], ct_fe) == mpk['gT']
            and NIZK.Batched_verify(self, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1'])
            and RangeProof.RanVerify(self.RangeProof, V, g, h, gs, hs, u, proof, seeds)
            and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
            and result_fe == [1] * N
            and result_z == True
            and result_CP == [1] * N
            and SEQ.verify(self.SEQ, pp, mpk['vk_seq'], pk_R['sigma_P'], pk_R['C_P'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge'])
        ):
            # --> L2.1: PRF and its proof
            ID_S = PRF.Gen(self.PRF, pp, sk[0]['seed'], sk[1] + 1)
            e1, e2, e3 = group.random(), group.random(), group.random()
            cm1 = Com.com(self.Com, pp_com, X, e1)
            cm2 = Com.com(self.Com, pp_com, sk[0]['seed'], e2)
            cm3 = Com.com(self.Com, pp_com, X + sk[0]['seed'], e3)
            w = (X, sk[0]['seed'], e1, e2, e3)
            x = (ID_S, cm1, cm2, cm3, pp_com['G'], pp_com['H'])
            x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma, x, w)

            # --> L2.2: FE.Dec(sk_x,ct_R) = g_T
            x = []; y=[]; c_b=[]
            for i in range(len(sk[0]['sk_fe'])):
                x.append(sk[0]['sk_fe'][i])
                y.append(ct_fe[i])
            c_a = [None]*N
            x.append(pp['G1']); y.append(mpk['g2'])
            c_a.append(mpk['g2'])
            c_b.extend(y)
            gamma1 = []
            for i in range(len(x)):
                if i < len(sk[0]['sk_fe']):
                    aux=[0]*len(y); aux[i]=1
                    gamma1.append(aux)
                else:
                    aux=[0]*len(y); aux[i]=-1
                    gamma1.append(aux)
            GS_X += x; GS_Y += y; GS_Ca += c_a; GS_Cb += c_b
            Gamma[1] = gamma1
                
        
              # --> L2.3: The SPS of seed and sk_fe
            c_b = []
            x = [pp['G1']**sk[0]['seed']]; y=[mpk['vk_sigA'][0]]
            for i in range(len(sk[0]['sk_fe'])):
                x.append(sk[0]['sk_fe'][i])
                y.append(mpk['vk_sigA'][i+1])
            x.extend([sk[0]['sigma_sig3']['R']])
            c_b.extend(y)
            c_a = [None]*(N+2)
            c_b.extend([None])
            y.extend([sk[0]['sigma_sig3']['T']])
            gamma2=[]
            for i in range(len(x)):
                if i <= len(sk[0]['sk_fe']):
                    aux=[0]*len(y); aux[i]=1
                    gamma2.append(aux)
                elif i == len(sk[0]['sk_fe'])+1:
                    aux=[0]*len(y); aux[i]=-1
                    gamma2.append(aux)
                elif i == len(sk[0]['sk_fe'])+2:
                    aux=[0]*len(y); aux[i]=1
                    gamma2.append(aux)
                else:
                    aux=[0]*len(y); aux[i]=-1
                    gamma2.append(aux)
            GS_X += x
            GS_Ca += c_a
            GS_Y += y
            GS_Cb += c_b
            Gamma[2] = gamma2

            # The second equation 
            x = [sk[0]['sigma_sig3']['S'], pp['G1']]
            c_a = [None, pp['G1']]
            y = [pp['G2'], sk[0]['sigma_sig3']['T']]
            c_b = [pp['G2'], None]
            GS_X += x
            GS_Ca += c_a
            GS_Y += y
            GS_Cb += c_b
            Gamma[3] = [[1,0],[0,-1]]

            # Gamma matrices
            n1 = len(Gamma[1])
            n2 = len(Gamma[2])
            n3 = len(Gamma[3])
            n_cols = len(Gamma[1][0]) + len(Gamma[2][0]) + len(Gamma[3][0])
            GammaT = [
                [row + [0] * (n_cols - n1) for row in Gamma[1]],
                [[0] * n1 + row + [0] * (n_cols - n1 - n2) for row in Gamma[2]],
                [[0] * (n1 + n2) + row for row in Gamma[3]],
            ]
            GammaT[0].extend([[0] * n_cols] * (n_cols - n1))
            aux1 = [[0] * n_cols] * n1
            aux1.extend(GammaT[1])
            aux1.extend([[0] * n_cols] * (n_cols - n1 - n2))
            GammaT[1] = aux1
            aux3 = [[0] * n_cols] * (n_cols - n3)
            aux3.extend(GammaT[2])
            GammaT[2] = aux3

            ind_x, ind_y = UPCS.matching(self, GS_X), UPCS.matching(self, GS_Y)
            GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK, mpk['CRS2'], GS_X, GS_Y, GS_Ca, GS_Cb, ind_x, ind_y)
            GS_proof = NIZK.prove(self.NIZK, mpk['CRS2'], GS_X, GS_Y, r, s, GS_comY, GammaT)

            # Bridge1: k & SPS sigma^3
            idx = GS_X.index(pp['G1'] ** sk[0]['seed'])
            w = (sk[0]['seed'], e2, r[idx][0], group.init(ZR, 0), r[idx][1])
            x = (
                cm2,
                GS_comX[idx][1],
                pp_com['G'],
                pp_com['H'],
                group.init(G1, 1),
                pp['G1'],
                mpk['CRS2']['vv1'][1],
                mpk['CRS2']['ww1'][1],
            )
            pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
            X_Bridge[1] = x
            Pi_Bridge[1] = pi

            sigma = DS.sign(self.DS, pp, sk[2], [mes, pk_R['ID']])
            LT2 = {'Gamma': GammaT, 'ind_x': ind_x, 'ind_y': ind_y}
            pi = {
                'pi': GS_proof,
                'comX': GS_comX,
                'comY': GS_comY,
                'x_prf': x_prf,
                'pi_prf': pi_prf,
                'X_Bridge': X_Bridge,
                'Pi_Bridge': Pi_Bridge,
            }
        else:
            print("There is no link")
            sigma = "perp"
            pi = "perp"
            LT2 = "perp"
        return {'sigma': sigma, 'pi': pi}, LT2


    def verify(self, mpk, pk_S, pk_R, mes, sigma):
        pp = mpk['pp']
        N = mpk['N']
        n = (N - 2) // 4

        pi_s = sigma['pi']

        # Verification for pk_R
        ct_feR = {}
        zR = {}
        C_PR = []
        x_feR = {}
        for i in range(N):
            ct_feR[i] = ((mpk['h'] ** (-pk_R['R'][i])) * pk_R['ct'][i])
            x_feR[i] = (pk_R['Phi'][i], mpk['ck'][i])

        # Verify knowledge of openings of GPC for pk_R
        result_feR = [
            1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma, x_feR[j], pk_R['pi_fe'][j])
        ]
        result_zR = True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zR[j], _,_) = pk_R['pi_fe'][j]
            C_PR.append(pk_R['ct'][j]/pk_R['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x != n+1 and x != N-1]:
                if zR[j][i] != group.init(0,ZR):
                    result_zR = False
        result_CPR = [1 for j in range(N) if C_PR[j] == pk_R['C_P'][j+2]]

        # Verification for pk_S
        ct_feS = {}
        zS = {}
        C_PS = []
        x_feS = {}
        for i in range(N):
            ct_feS[i] = ((mpk['h'] ** (-pk_S['R'][i])) * pk_S['ct'][i])
            x_feS[i] = (pk_S['Phi'][i], mpk['ck'][i])

        # Verify knowledge of openings of GPC for pk_S
        result_feS = [
            1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma, x_feS[j], pk_S['pi_fe'][j])
        ]
        result_zS = True

        # Check zero positions in vector phi for pk_S
        for j in range(N):
            (zS[j], s, C_0) = pk_S['pi_fe'][j]
            C_PS.append(pk_S['ct'][j] / pk_S['Phi'][j])
            for i in [x for x in range(N) if x != 0 and x != n + 1 and x != N - 1]:
                if zS[j][i] != group.init(0, ZR):
                    result_zS = False

        result_CPS = [1 for j in range(N) if C_PS[j] == pk_S['C_P'][j + 2]]

        (V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) = pk_S['rp']
        (V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) = pk_R['rp']

        # Perform all verifications
        if (
            NIZK.verify(self, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1'])
            and NIZK.verify(self, pp, mpk['CRS1'], pk_S['pi'], pk_S['comX'], pk_S['comY'], mpk['LT1'])
            and RangeProof.RanVerify(
                self, V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S
            )
            and RangeProof.RanVerify(self, V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R)
            and Sigma.PRFprove.Verify(self.Sigma, pk_S['x_prf'], pk_S['pi_prf'])
            and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
            and result_feR == [1] * N
            and result_zR
            and result_CPR == [1] * N
            and SEQ.verify(self.SEQ, pp, mpk['vk_seq'], pk_R['sigma_P'], pk_R['C_P'])
            and result_feS == [1] * N
            and result_zS
            and result_CPS == [1] * N
            and SEQ.verify(self.SEQ, pp, mpk['vk_seq'], pk_S['sigma_P'], pk_S['C_P'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_S['X_Bridge'], pk_S['Pi_Bridge'])
        ):
            print("Valid sender's and receiver's public key\n")

        # Perform final verifications
        return (
            DS.verify(self.DS, pp, pk_S['vk_sig'], sigma['sigma'], [mes, pk_R['ID']])
            and NIZK.verify(
                self, pp, mpk['CRS2'], pi_s['pi'], pi_s['comX'], pi_s['comY'], mpk['LT2']
            )
            and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
            and Sigma.D_Bridging.Verify(self.Sigma, pi_s['X_Bridge'], pi_s['Pi_Bridge'])
        )

    def Batched_verify(self,mpk,pk_S,pk_R,mes,sigma):
        pp = mpk['pp']
        N = mpk['N']
        n = (N - 2) // 4

        pi_s = sigma['pi']

        # Verification for pk_R
        ct_feR = {}
        zR = {}
        C_PR = []
        x_feR = {}
        for i in range(N):
            ct_feR[i] = ((mpk['h'] ** (-pk_R['R'][i])) * pk_R['ct'][i])
            x_feR[i] = (pk_R['Phi'][i], mpk['ck'][i])

        # Verify knowledge of openings of GPC for pk_R
        result_feR = [
            1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma, x_feR[j], pk_R['pi_fe'][j])
        ]
        result_zR=True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zR[j], s, C_0) = pk_R['pi_fe'][j]
            C_PR.append(pk_R['ct'][j]/pk_R['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x != n+1 and x != N-1]:
                if zR[j][i] != group.init(0,ZR):
                    result_zR = False
        result_CPR= [1 for j in range(N) if C_PR[j] == pk_R['C_P'][j+2]]

        # Verification for pk_S
        ct_feS = {}
        zS = {}
        C_PS = []
        x_feS = {}
        for i in range(N):
            ct_feS[i] = ((mpk['h'] ** (-pk_S['R'][i])) * pk_S['ct'][i])
            x_feS[i] = (pk_S['Phi'][i], mpk['ck'][i])

        # Verify knowledge of openings of GPC for pk_S
        result_feS = [
            1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma, x_feS[j], pk_S['pi_fe'][j])
        ]
        result_zS = True

        # Check zero positions in vector phi for pk_S
        for j in range(N):
            (zS[j], _, _) = pk_S['pi_fe'][j]
            C_PS.append(pk_S['ct'][j] / pk_S['Phi'][j])
            for i in [x for x in range(N) if x != 0 and x != n + 1 and x != N - 1]:
                if zS[j][i] != group.init(0, ZR):
                    result_zS = False

        result_CPS = [1 for j in range(N) if C_PS[j] == pk_S['C_P'][j + 2]]

        (V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) = pk_S['rp']
        (V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) = pk_R['rp']

        # Perform all verifications
        if (
            NIZK.Batched_verify(self, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1'])
            and NIZK.Batched_verify(self, pp, mpk['CRS1'], pk_S['pi'], pk_S['comX'], pk_S['comY'], mpk['LT1'])
            and RangeProof.RanVerify(
                self, V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S
            )
            and RangeProof.RanVerify(self, V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R)
            and Sigma.PRFprove.Verify(self.Sigma, pk_S['x_prf'], pk_S['pi_prf'])
            and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
            and result_feR == [1] * N
            and result_zR
            and result_CPR == [1] * N
            and SEQ.verify(self.SEQ, pp, mpk['vk_seq'], pk_R['sigma_P'], pk_R['C_P'])
            and result_feS == [1] * N
            and result_zS
            and result_CPS == [1] * N
            and SEQ.verify(self.SEQ, pp, mpk['vk_seq'], pk_S['sigma_P'], pk_S['C_P'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_S['X_Bridge'], pk_S['Pi_Bridge'])
        ):
            print("Valid sender's and receiver's public key\n")

        # Perform final verifications
        return (
            DS.verify(self.DS, pp, pk_S['vk_sig'], sigma['sigma'], [mes, pk_R['ID']])
            and NIZK.Batched_verify(
                self, pp, mpk['CRS2'], pi_s['pi'], pi_s['comX'], pi_s['comY'], mpk['LT2']
            )
            and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
            and Sigma.D_Bridging.Verify(self.Sigma, pi_s['X_Bridge'], pi_s['Pi_Bridge'])
        )