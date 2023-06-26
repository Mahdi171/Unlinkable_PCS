import numpy as np

class Policy():
    def maker(self,n_R):
        F_lambda=np.random.randint(2, size=(n_R,n_R))
        S = np.random.randint(2, size=n_R)
        R = np.random.randint(2, size=n_R)
        for x in range(n_R):
            for y in range(n_R):
                F_lambda[x,y]=S[x]&R[y]
        return {'S':S,'R':R,'F':F_lambda}
