from charm.toolbox.pairinggroup import pair


class SPS():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj

    def keygen(self, pp, l):
        sk={}; vk={}
        for i in range(l):
            sk[i]=group.random()
            vk[i]=pp['G2']**sk[i]
        return (sk,vk)
        
    def sign(self, pp, sk, M):
        a= group.random()
        R=1
        for i in range(len(M)):
            R*=M[i]**sk[i]
        sigma={'R':R**a, 'S':pp['G1']**(a**(-1)),'T':pp['G2']**(a**(-1))}
        return sigma
        
    def verify(self, pp, vk, sigma, M):
        LHS=1
        for i in range(len(M)):
            LHS*=pair(vk[i],M[i])
        return LHS==pair(sigma['R'],sigma['T']) and pair(sigma['S'],pp['G2'])==pair(pp['G1'],sigma['T'])