
class ElGamal():
    def __init__(self, groupObj, p=0, q=0):
        global group
        group = groupObj

    def keygen(self, pp):
        x = group.random(); pk = pp['G1'] ** x
        return x, pk
    def Enc(self,pp, pk, M):
        r = group.random()
        return {'c1':pp['G1'] ** r, 'c2':M * (pk ** r)},r
    def Dec(self, sk, c):
        return c['c2']/(c['c1'] ** sk)
