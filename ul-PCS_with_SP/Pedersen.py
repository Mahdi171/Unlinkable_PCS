from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair


class PedCom():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Setup(self):
        G = group.random(G1); H = group.random(G1)
        return {'G':G, 'H':H}
    def com(self,pp,m,tau):
        return (pp['G']**m) * (pp['H']**tau)
    def verify(self,pp,cm,m,tau):
        if cm== (pp['G']**m) * (pp['H']**tau):
            return 1
        else:
            return 0
    