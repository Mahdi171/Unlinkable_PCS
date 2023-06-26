
class DY():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Gen(self,pp,seed,k):
        return pp['G1']**((seed+k)**(-1))
    