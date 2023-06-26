class DY():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Gen(self,pp,seed,k):
        return pp['G']**((seed+k)**(-1))