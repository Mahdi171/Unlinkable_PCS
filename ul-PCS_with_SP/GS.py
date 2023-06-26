from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from openpyxl import Workbook
import numpy as np
from functools import reduce
import time
from itertools import combinations
 
class GS():
    def __init__(self, groupObj):
        global util, group
        group = groupObj

    def Trusted_Setup(self,pp):
    # To sample four different scalars from \Z_p.
        rho, zeta, sigma, omega = [group.random() for _ in range(4)]
        vv1 = [pp['G1']**zeta, pp['G1']]
        vv2 = [pp['G2']**omega, pp['G2']]
        ww1 = [pp['G1']**(rho*zeta), pp['G1']**rho]
        ww2 = [pp['G2']**(sigma*omega), pp['G2']*sigma]
        Zeta = [-zeta**(-1), 1]
        Omega = [-omega**(-1), 1]
        crs = {'vv1':vv1, 'vv2':vv2, 'ww1':ww1, 'ww2':ww2}
        # trapdoors: one can use public randomness techniques to avoid them.
        tpd = {'crs':crs, 'Zeta':Zeta, 'Omega': Omega}
        return crs, tpd

    def Transpatent_Setup(self,pp):
        vv1 = [group.random(G1), pp['G1']]
        vv2 = [group.random(G2), pp['G2']]
        ww1 = [group.random(G1), pp['G1']]
        ww2 = [group.random(G2), pp['G2']]
        crs = {'vv1':vv1, 'vv2':vv2, 'ww1':ww1, 'ww2':ww2}
        tpd = {'empty'}
        return crs, tpd
    
    def commit(self, crs , X, Y, C_x, C_y, ind_x, ind_y):
        com_x = []; com_y = []
        n = len(X); m = len(Y)
        r = [([group.init(ZR,0),group.init(ZR,0)] if C_x[i] != None \
               else [group.random(),group.random()]) for i in range(len(C_x))]
        s = [([group.init(ZR,0),group.init(ZR,0)] if C_y[i] != None \
               else [group.random(),group.random()]) for i in range(len(C_y))]
        
        for i in range(len(ind_x)):
            repated_rands_x = [group.random(),group.random()]
            for value in ind_x[i]:
                if C_x[value] == None:
                    r[value] = repated_rands_x
        for i in range(len(ind_y)):
            repated_rands_y = [group.random(),group.random()]
            for value in ind_y[i]:
                if C_y[value] == None:
                    s[value] = repated_rands_y
        for i in range(n):
            com_x.append([(crs['vv1'][0]**r[i][0])*(crs['ww1'][0]**r[i][1]),\
                           X[i]*(crs['vv1'][1]**r[i][0])*(crs['ww1'][1]**r[i][1])])
        for i in range(m):
            com_y.append([(crs['vv2'][0]**s[i][0])*(crs['ww2'][0]**s[i][1]),\
                           Y[i]*(crs['vv2'][1]**s[i][0])*(crs['ww2'][1]**s[i][1])])
        return com_x, com_y, r, s
    
    def prove(self, crs, X, Y, r, s, com_y, GammaT):
        proof = {}
        n = len(X); m = len(Y)
        for ii in range(len(GammaT)):
            gammaT = GammaT[ii]; Com_y = {}; Xp={}
            alpha, beta, gamma, delta = [group.random() for _ in range(4)]
            for j in range(n):
                aux1 = 1; aux2 = 1; aux3 = 1
                for k in range(m):
                    aux1 *= com_y[k][0]**gammaT[k][j]
                    aux2 *= com_y[k][1]**gammaT[k][j]
                    aux3 *= X[k]**gammaT[j][k]
                Com_y[j] = [aux1, aux2]
                Xp[j] = aux3
            
            pi_v1 = [reduce(lambda x, y: x * y, [Com_y[i][0]**r[i][0] for i in range(m)]) * crs['vv2'][0]**alpha * crs['ww2'][0]**beta,\
                    reduce(lambda x, y: x * y, [Com_y[i][1]**r[i][0] for i in range(m)]) * crs['vv2'][1]**alpha * crs['ww2'][1]**beta]
            pi_w1 = [reduce(lambda x, y: x * y, [Com_y[i][0]**r[i][1] for i in range(m)]) * crs['vv2'][0]**gamma * crs['ww2'][0]**delta,\
                    reduce(lambda x, y: x * y, [Com_y[i][1]**r[i][1] for i in range(m)]) * crs['vv2'][1]**gamma * crs['ww2'][1]**delta]
            pi_v2 = [crs['vv1'][0]**-alpha * crs['ww1'][0]**(-gamma),\
                    reduce(lambda x, y: x * y, [Xp[i]**s[i][0] for i in range(n)]) * crs['vv1'][1]**-alpha * crs['ww1'][1]**-gamma]
            pi_w2 = [crs['vv1'][0]**-beta * crs['ww1'][0]**(-delta),\
                    reduce(lambda x, y: x * y, [Xp[i]**s[i][1] for i in range(n)]) * crs['vv1'][1]**-beta * crs['ww1'][1]**-delta]
            proof[ii] = {'pi_v1': pi_v1, 'pi_w1': pi_w1, 'pi_v2': pi_v2, 'pi_w2': pi_w2}
        return proof
    
    def verify(self, pp, crs, proof, com_x, com_y, LT):
        # Initialize dictionaries and LHS
        p1 = {}; p2 = {}; LHS = 1; GammaT=LT['Gamma']
        # Compute an extended bilinear pairing on the received valus
        for i in range(len(LT['ind_x'])):
            for value1 in LT['ind_x'][i]:
                for value2 in LT['ind_x'][i]:
                    if com_x[value1] != com_x[value2]:
                        return False
        for i in range(len(LT['ind_y'])):
            for value1, value2 in combinations(LT['ind_y'][i], 2):
                if com_y[value1] != com_y[value2]:
                    return False
        for ii in range(len(GammaT)):
            gammaT = GammaT[ii]
            Pi = proof[ii]
            #com_x = Com_x[ii]; com_y = Com_y[ii]
            # Set N to the length of com_x and the lengh of com_y
            n = len(com_x); m = len(com_y)
            for vv1 in [0, 1]:
                for vv2 in [0, 1]:
                    for i in range(n):
                        p1[i] = com_x[i][vv1]
                        p2[i] = 1
                        for j in range(m):
                            p2[i] *= com_y[j][vv2]**gammaT[j][i]
                    
                    p1.update({i:crs['vv1'][vv1]**-1 if i == m else crs['ww1'][vv1]**-1 if i == m+1 \
                                else Pi['pi_v2'][vv1] if i == m+2 else Pi['pi_w2'][vv1] for i in range(m,m+4)})
                    p2.update({i:Pi['pi_v1'][vv2] if i == m else Pi['pi_w1'][vv2] if i == m+1 \
                                else crs['vv2'][vv2]**-1 if i == m+2 else crs['ww2'][vv2]**-1 for i in range(m,m+4)})
                    # Compute the pairing of each element in p1 and p2, and multiply them all and keep them in LHS
                    LHS = reduce(lambda x, y: x * y, [pair(p1[k], p2[k]) for k in range(m+4)])
                    if LHS != pp['GT']**0:
                        return False
            # Checrs if LHS is equal to the identity value in GT, i.e. pp['GT']**0, and return the result
        return True
    # The batched verification algorithm reduces the number of pairings to N+4
    def Batched_verify(self, pp, crs, proof, com_x, com_y, LT):
        # Initialize dictionaries and LHS
        p1 = {}; p2 = {}; LHS = 1; GammaT = LT['Gamma']
        # Set m to the length of com_x and n to the lengh of com_y
        P1 = {}; P2 = {}

        for i in range(len(LT['ind_x'])):
            for value1 in LT['ind_x'][i]:
                for value2 in LT['ind_x'][i]:
                    if com_x[value1] != com_x[value2]:
                        return False
        for i in range(len(LT['ind_y'])):
            for value1, value2 in combinations(LT['ind_y'][i], 2):
                if com_y[value1] != com_y[value2]:
                    print("y")
                    return False
        S = [group.random(), group.random()]
        R = [group.random(), group.random()]
        # Loop over all possible combinations of vv1 and vv2
        for ii in range(len(GammaT)):
            gammaT = GammaT[ii]
            Pi = proof[ii]
            #com_x = Com_x[ii]; com_y = Com_y[ii]
            m = len(com_x); n = len(com_y)
            for vv1 in [0, 1]:
                for vv2 in [0, 1]:
                    for i in range(m):
                        p1[i] = com_x[i][vv1]
                        p2[i] = 1
                        for j in range(n):
                            p2[i] *= com_y[j][vv2]**gammaT[j][i]
            for vv1 in [0, 1]:
                p1.update({i:(crs['vv1'][vv1]**-1 if i == m else crs['ww1'][vv1]**-1 if i == m+1 \
                            else Pi['pi_v2'][vv1] if i == m+2 else Pi['pi_w2'][vv1]) for i in range(m,m+4)})
                P1[vv1] = p1
                p2.update({i: (Pi['pi_v1'][vv1] if i == m else Pi['pi_w1'][vv1] if i == m+1 \
                            else crs['vv2'][vv1]**-1 if i == m+2 else crs['ww2'][vv1]**-1) for i in range(m,m+4)})
                P2[vv1] = p2
                # Compute the pairing of each element in p1 and p2, and multiply them all and keep them in LHS
            P1 = [(P1[0][i]**S[0])*(P1[1][i]**S[1]) for i in range(len(P1[0]))]
            P2 = [(P2[0][i]**R[0])*(P2[1][i]**R[1]) for i in range(len(P2[0]))]
            LHS = reduce(lambda x, y: x * y, [pair(P1[k], P2[k]) for k in range(m+4)])
            # Checrs if LHS is equal to the identity value in GT, i.e. pp['GT']**0, and return the result
            if LHS != pp['GT']**0:
                return False
        return True
