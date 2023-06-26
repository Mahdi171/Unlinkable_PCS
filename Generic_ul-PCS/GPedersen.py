from charm.toolbox.pairinggroup import G2


class GPed():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj
    def Setup(self,n):
        ck=[group.random(G2)]
        for _ in range(n):
            ck.append(group.random(G2))
        return ck
    def Comm(self,ck,x,r):
        c=ck[0]**r
        for i in range(len(x)):
            c*=ck[i+1]**x[i]
        return c
    def verify(self,ck,c,x,r):
        cp=ck[0]**r
        for i in range(len(x)):
            cp*=ck[i+1]**x[i]
        return c==cp