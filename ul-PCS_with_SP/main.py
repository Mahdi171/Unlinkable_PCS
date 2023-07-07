#!/usr/bin/env python3.8.3
from charm.toolbox.pairinggroup import PairingGroup,ZR,G2,G1
from charm.core.engine.util import objectToBytes
from BLS import BLS01 as DS
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com
from ElGamal import ElGamal as ENC

groupObj = PairingGroup('BN254')
class UPCS():
    def __init__(self, groupObj):
        global group
        group = groupObj
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.Policy = Policy()
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma = Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
        self.Enc = ENC(groupObj)

    def matching(self, lst):
        indices_dict = {}
        for i, element in enumerate(lst):
            indices_dict.setdefault(element, []).append(i)
        # Filter the dictionary to include only elements with multiple occurrences
        repeated_elements = [indices for element, indices in indices_dict.items() if len(indices) > 1]
        return repeated_elements

    def Setup(self, F):
        Gamma1 = {}
        Gamma2 = {}
        pp = BG.Gen(self)
        CRS1, tpd1 = NIZK.Transpatent_Setup(self, pp)
        CRS2, tpd2 = NIZK.Transpatent_Setup(self, pp)
        pp_com = Com.Setup(self)
        (sk_sigAS, vk_sigAS) = SPS.keygen(self.SPS, pp, 3)
        (sk_sigAR, vk_sigAR) = SPS.keygen(self.SPS, pp, 3)
        (dk_encA, ek_encA) = ENC.keygen(self.Enc, pp)
        msk = {'sk_sigAS': sk_sigAS, 'sk_sigAR': sk_sigAR, 'dk_encA': dk_encA}
        mpk = {'pp': pp, 'CRS1': CRS1, 'CRS2': CRS2, 'vk_sigAS': vk_sigAS,
               'vk_sigAR': vk_sigAR, 'ek_encA': ek_encA, 'pp_com': pp_com}
        x, v = 0, 0
        while True:
            if F['R'][x] and F['S'][v]:
                sk, pk, LT1 = self.KeyGen(mpk, msk, x, F)
                sk_R, pk_R, LT1 = self.KeyGen(mpk, msk, v, F)
                mpk['LT1'] = LT1
                sigma, LT2 = self.Sign(mpk, sk, pk_R, groupObj.random())
                mpk['LT2'] = LT2
                break
            x += 1
            v += 1
        return (msk, mpk)


    def KeyGen(self, mpk, msk, x, F):
        seed = group.random()
        pp = mpk['pp']

        if F['R'][x] == 1:
            m = group.init(ZR, 1)
            m_x = pp['G1'] ** m
            sigma_sigR = SPS.sign(self.SPS, pp, msk['sk_sigAR'], [pp['G1'] ** seed, pp['G1'] ** msk['dk_encA'], m_x])
            flag_R = 1
        else:
            m = group.init(ZR, 0)
            m_x = pp['G1'] ** m
            sigma_sigR = SPS.sign(self.SPS, pp, msk['sk_sigAR'], [pp['G1'] ** seed, mpk['ek_encA'], m_x])
            flag_R = 0

        (sk_sig, vk_sig) = DS.keygen(self.DS, pp)

        if F['S'][x] == 1:
            sigma_sigS = SPS.sign(self.SPS, pp, msk['sk_sigAS'], [pp['G1'] ** seed, pp['G1'] ** msk['dk_encA']])
            flag_S = 1
            usk = {
                'seed': seed,
                'sk_sig': sk_sig,
                'vk_sig': vk_sig,
                'sigma_sigS': sigma_sigS,
                'sigma_sigR': sigma_sigR,
                'm': m_x,
                'dk_encA': msk['dk_encA'],
                'flag_S': flag_S,
                'flag_R': flag_R
            }
        else:
            flag_S = 0
            usk = {
                'seed': seed,
                'sk_sig': sk_sig,
                'vk_sig': vk_sig,
                'sigma_sigR': sigma_sigR,
                'm': m_x,
                'flag_S': flag_S,
                'flag_R': flag_R
            }

        sk = [usk, -1, "perp", "perp", "perp"]
        return self.RandKey(mpk, sk)

    

    def RandKey(self, mpk, sk):
        pp = mpk['pp']
        pp_com = mpk['pp_com']
        GS_proof = {}
        GS_comX = {}
        GS_comY = {}
        GS_X = []
        GS_Y = []
        GS_Ca = []
        GS_Cb = []
        Gamma = {}
        X = sk[1] + 1
        X_Bridge = {}
        Pi_Bridge = {}

        # --> L1.1: PRF and its proof
        ID = PRF.Gen(self, pp_com, sk[0]['seed'], X)
        e1, e2, e3 = group.random(), group.random(), group.random()
        cm1 = Com.com(self, pp_com, X, e1)
        cm2 = Com.com(self, pp_com, sk[0]['seed'], e2)
        cm3 = Com.com(self, pp_com, X + sk[0]['seed'], e3)
        w = (X, sk[0]['seed'], e1, e2, e3)
        x = (ID, cm1, cm2, cm3, pp_com['G'], pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma, x, w)

        # --> L1.2: range_proof
        v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V = RangeProof.Setup(self.RangeProof, X, 16)
        proof = RangeProof.RanProve(self.RangeProof, v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp = (V, g, h, gs, hs, u, proof, seeds)

        # --> Bridge1: ctr
        gamma = group.random()
        com_aux = Com.com(self, pp_com, X, gamma)
        w = (X, e1, gamma, 0, 0)
        x = (cm1, com_aux, pp_com['G'], pp_com['H'], group.init(G1, 1), pp_com['G'], pp_com['H'], group.init(G1, 1))
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[1] = x
        Pi_Bridge[1] = pi

        # --> L1.3: SPS verification proof
        x = [pp['G1'] ** sk[0]['seed']]
        c_a = [None]
        if sk[0]['flag_R'] == 1:
            x.append(pp['G1'] ** sk[0]['dk_encA'])
            c_a.append(None)
        else:
            x.append(mpk['ek_encA'])
            c_a.append(mpk['ek_encA'])
        x.extend([sk[0]['m'], sk[0]['sigma_sigR']['R']])
        y = [mpk['vk_sigAR'][0], mpk['vk_sigAR'][1], mpk['vk_sigAR'][2], sk[0]['sigma_sigR']['T']]
        c_a.extend([sk[0]['m'], None])
        c_b = [mpk['vk_sigAR'][0], mpk['vk_sigAR'][1], mpk['vk_sigAR'][2], None]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b
        Gamma[1] = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, -1]]

        # second equation
        x = [sk[0]['sigma_sigR']['S'], pp['G1']]
        y = [pp['G2'], sk[0]['sigma_sigR']['T']]
        c_a = [None, pp['G1']]
        c_b = [pp['G2'], None]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b
        Gamma[2] = [[1, 0], [0, -1]]

        sk_sig, vk_sig = DS.keygen(self, pp)
        sigma_sig = DS.sign(self, pp, sk[0]['sk_sig'], [vk_sig, ID])
        sk[3] = sigma_sig
        ct, r = ENC.Enc(self, pp, mpk['ek_encA'], sk[0]['m'])
        sk[4] = r

        # --> L1.4: Proof of knowledge of encryption
        tau = group.random()
        cm = Com.com(self, pp_com, group.init(ZR, 1), tau)
        x_elgamal = (ct['c1'], ct['c2'], mpk['ek_encA'], cm, pp_com['G'], pp_com['H'])
        w_elgamal = (r, group.init(ZR, 1), tau)
        pi_elgamal = Sigma.ElGamal.Prove(self.Sigma, pp, x_elgamal, w_elgamal)

        # --> L1.5: Proof of knowledge of BLS signature
        x = [sk[0]['vk_sig'], pp['G1']]
        y = [group.hash(objectToBytes([vk_sig, ID], group), G2), sigma_sig]
        c_a = [None, pp['G1']]
        c_b = [group.hash(objectToBytes([vk_sig, ID], group), G2), None]
        GS_X += x
        GS_Ca += c_a
        GS_Y += y
        GS_Cb += c_b
        Gamma[3] = [[1, 0], [0, -1]]

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
        

        ind_x, ind_y = UPCS.matching(self,GS_X),UPCS.matching(self,GS_Y)
        GS_comX, GS_comY, r, s = NIZK.commit(self.NIZK,mpk['CRS1'],GS_X,GS_Y,GS_Ca,GS_Cb,ind_x,ind_y)
        GS_proof = NIZK.prove(self.NIZK,mpk['CRS1'],GS_X,GS_Y,r,s,GS_comY,GammaT)

        # --> Bridge2: k
        w = (sk[0]['seed'], e2, r[0][0], group.init(ZR, 0), r[0][1])
        x = (cm2, GS_comX[0][1], pp_com['G'], pp_com['H'], group.init(G1, 1), pp['G1'], mpk['CRS1']['vv1'][1], mpk['CRS1']['ww1'][1])
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[2] = x
        Pi_Bridge[2] = pi

        # --> Bridge3: m_x
        w = (group.init(ZR, 1), r[2][0], tau, r[2][1], group.init(ZR, 0))
        x = (GS_comX[2][1], cm, pp['G1'], mpk['CRS1']['vv1'][1], mpk['CRS1']['ww1'][1], pp_com['G'], pp_com['H'], group.init(G1, 1))
        pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
        X_Bridge[3] = x
        Pi_Bridge[3] = pi

        LT1 = {'Gamma': GammaT, 'ind_x': ind_x, 'ind_y': ind_y}
        sk[1] += 1
        sk[2] = sk_sig
        sk[3] = sigma_sig
        pk = {
            'ID': ID,
            'vk_sig': vk_sig,
            'ct': ct,
            'comX': GS_comX,
            'comY': GS_comY,
            'pi': GS_proof,
            'rp': rp,
            'x_prf': x_prf,
            'pi_prf': pi_prf,
            'pi_elgamal': pi_elgamal,
            'x_elgamal': x_elgamal,
            'X_Bridge': X_Bridge,
            'Pi_Bridge': Pi_Bridge
        }
        return sk, pk, LT1

    def Sign(self, mpk, sk, pk_R, m):
        pp = mpk['pp']
        pp_com = mpk['pp_com']
        (V, g, h, gs, hs, u, proof, seeds) = pk_R['rp']
        X = sk[1] + 1
        GS_proof = {}
        GS_comX = {}
        GS_comY = {}
        res_Bridge = []
        GS_X = []
        GS_Y = []
        GS_Ca = []
        GS_Cb = []
        Gamma = {}
        X_Bridge = {}
        Pi_Bridge = {}

        if 'dk_encA' in sk[0].keys() and NIZK.Batched_verify(
                self.NIZK, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1']
        ) and ENC.Dec(self, sk[0]['dk_encA'], pk_R['ct']) == pp['G1'] ** group.init(ZR, 1) and \
                RangeProof.RanVerify(self.RangeProof, V, g, h, gs, hs, u, proof, seeds) and \
                Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf']) and \
                Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge']):
            print('The public key of the receiver is valid\n')

            # --> L2.1: PRF proof and its proof
            ID_S = PRF.Gen(self, pp_com, sk[0]['seed'], sk[1])
            e1, e2, e3 = group.random(), group.random(), group.random()
            cm1 = Com.com(self, pp_com, X, e1)
            cm2 = Com.com(self, pp_com, sk[0]['seed'], e2)
            cm3 = Com.com(self, pp_com, X + sk[0]['seed'], e3)
            w = (X, sk[0]['seed'], e1, e2, e3)
            x = (ID_S, cm1, cm2, cm3, pp_com['G'], pp_com['H'])
            x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma, x, w)

            # --> L2.2: SPS proof
            x = [pp['G1'] ** sk[0]['seed'], pp['G1'] ** sk[0]['dk_encA'], sk[0]['sigma_sigS']['R']]
            y = [mpk['vk_sigAS'][0], mpk['vk_sigAS'][1], sk[0]['sigma_sigS']['T']]
            c_a = [None, None, None]
            c_b = [mpk['vk_sigAS'][0], mpk['vk_sigAS'][1], None]
            GS_X += x
            GS_Ca += c_a
            GS_Y += y
            GS_Cb += c_b
            Gamma[1] = [[1, 0, 0], [0, 1, 0], [0, 0, -1]]

            # Second equation
            x = [sk[0]['sigma_sigS']['S'], pp['G1']]
            y = [pp['G2'], sk[0]['sigma_sigS']['T']]
            c_a = [None, pp['G1']]
            c_b = [pp['G2'], None]
            GS_X += x
            GS_Ca += c_a
            GS_Y += y
            GS_Cb += c_b
            Gamma[2] = [[1, 0], [0, -1]]
                    
            # Gamma matrices
            n1 = len(Gamma[1])
            n2 = len(Gamma[2])
            n_cols = len(Gamma[1][0]) + len(Gamma[2][0])
            GammaT = [[row + [0]*(n_cols-n1) for row in Gamma[1]],
                    [[0]*(n1) + row for row in Gamma[2]]]
            GammaT[0].extend([[0]*n_cols]*(n_cols - n1))
            aux1 = [[0]*n_cols]*n1
            aux1.extend(GammaT[1])
            aux1.extend([[0]*n_cols]*(n_cols - n1 - n2))
            GammaT[1] = aux1

            ind_x, ind_y = UPCS.matching(self, GS_X), UPCS.matching(self, GS_Y)
            GS_comX, GS_comY, r, s = NIZK.commit(
                self.NIZK, mpk['CRS2'], GS_X, GS_Y, GS_Ca, GS_Cb, ind_x, ind_y
            )
            GS_proof = NIZK.prove(
                self.NIZK, mpk['CRS2'], GS_X, GS_Y, r, s, GS_comY, GammaT
            )

            # --> Bridge1: k
            w = (sk[0]['seed'], e2, r[0][0], group.init(ZR, 0), r[0][1])
            x = (
                cm2,
                GS_comX[0][1],
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

            # --> L2.3:
            # --> L2.4: To prove the knowledge of dk^A under the public ek^A
            ins = (pp['G1'], mpk['ek_encA'])
            wit = (sk[0]['dk_encA'])
            e1 = group.random()
            cm = Com.com(self, pp_com, sk[0]['dk_encA'], e1)
            x_dk, pi_dk = Sigma.Dlog.Prove(self.Sigma, ins, wit)

            # --> Bridge2: sk_PKE^A
            w = (sk[0]['dk_encA'], e1, r[1][0], group.init(ZR, 0), r[1][1])
            x = (
                cm,
                GS_comX[1][1],
                pp_com['G'],
                pp_com['H'],
                group.init(G1, 1),
                pp['G1'],
                mpk['CRS2']['vv1'][1],
                mpk['CRS2']['ww1'][1],
            )
            pi = Sigma.D_Bridging.Prove(self.Sigma, x, w)
            X_Bridge[2] = x
            Pi_Bridge[2] = pi

            sigma = DS.sign(self, pp, sk[2], [m, pk_R['ID']])
            pi = {
                'pi': GS_proof,
                'comX': GS_comX,
                'comY': GS_comY,
                'x_prf': x_prf,
                'pi_prf': pi_prf,
                'x_dk': x_dk,
                'pi_dk': pi_dk,
                'X_Bridge': X_Bridge,
                'Pi_Bridge': Pi_Bridge,
            }
            LT2 = {'Gamma': GammaT, 'ind_x': ind_x, 'ind_y': ind_y}
        else:
            print("There is no link")
            sigma = "perp"
            pi = "perp"
            LT2 = "perp"
        return {'sigma': sigma, 'pi': pi}, LT2


    def verify(self, mpk, pk_S, pk_R, m, sigma):
        pi_s = sigma['pi']
        pp = mpk['pp']
        if (
            NIZK.verify(self.NIZK, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1'])
            and NIZK.verify(self.NIZK, pp, mpk['CRS1'], pk_S['pi'], pk_S['comX'], pk_S['comY'], mpk['LT1'])
            and Sigma.Dlog.Verify(self.Sigma, pi_s['x_dk'], pi_s['pi_dk'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_S['X_Bridge'], pk_S['Pi_Bridge'])
        ):
            print("Valid sender's and receiver's public key\n")
            return (
                DS.verify(self, mpk['pp'], pk_S['vk_sig'], sigma['sigma'], [m, pk_R['ID']])
                and NIZK.verify(self.NIZK, pp, mpk['CRS2'], pi_s['pi'], pi_s['comX'], pi_s['comY'], mpk['LT2'])
                and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
                and Sigma.D_Bridging.Verify(self.Sigma, pi_s['X_Bridge'], pi_s['Pi_Bridge'])
            )


    def Batched_verify(self, mpk, pk_S, pk_R, m, sigma):
        pi_s = sigma['pi']
        pp = mpk['pp']
        if (
            NIZK.Batched_verify(self.NIZK, pp, mpk['CRS1'], pk_R['pi'], pk_R['comX'], pk_R['comY'], mpk['LT1'])
            and NIZK.Batched_verify(self.NIZK, pp, mpk['CRS1'], pk_S['pi'], pk_S['comX'], pk_S['comY'], mpk['LT1'])
            and Sigma.Dlog.Verify(self.Sigma, pi_s['x_dk'], pi_s['pi_dk'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_R['X_Bridge'], pk_R['Pi_Bridge'])
            and Sigma.D_Bridging.Verify(self.Sigma, pk_S['X_Bridge'], pk_S['Pi_Bridge'])
        ):
            print("Valid sender's and receiver's public key\n")
            return (
                DS.verify(self, mpk['pp'], pk_S['vk_sig'], sigma['sigma'], [m, pk_R['ID']])
                and NIZK.Batched_verify(self.NIZK, pp, mpk['CRS2'], pi_s['pi'], pi_s['comX'], pi_s['comY'], mpk['LT2'])
                and Sigma.PRFprove.Verify(self.Sigma, pk_R['x_prf'], pk_R['pi_prf'])
                and Sigma.D_Bridging.Verify(self.Sigma, pi_s['X_Bridge'], pi_s['Pi_Bridge'])
            )
