from charm.toolbox.pairinggroup import G1, G2


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


class GPed():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj
    def Setup(self,n):
        ck=[group.random(G2)]
        for _ in range(n):
            ck.append(group.random(G2))
        return ck
    def Com(self,ck,x,r):
        c=ck[0]**r
        for i in range(len(x)):
            c*=ck[i+1]**x[i]
        return c
    def verify(self,ck,c,x,r):
        cp=ck[0]**r
        for i in range(len(x)):
            cp*=ck[i+1]**x[i]
        return c==cp