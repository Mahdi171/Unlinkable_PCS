from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair


debug = False


class BG():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj
        
    def Gen(self):
        g1,g2=group.random(G1),group.random(G2)
        return {'G1':g1,'G2':g2,'GT':pair(g1,g2)}