from charm.toolbox.pairinggroup import pair
from charm.toolbox.IBSig import *

class ACC():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Create(self,pp):
        alpha=group.random()
        A=pp['G2']**alpha
        msk=alpha
        return (A,msk)
    def Add(self,pp,A,msk,x):
        if A==pp['G2']**msk:
            w_x=pp['G1']**((x+msk)**(-1))
        return w_x
    def MemVrf(self, pp, A, x, w_x):
        if pp['GT']==pair(w_x,A*(pp['G2']**x)):
            return True
        else: return False