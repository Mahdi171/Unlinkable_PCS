from email import policy
import numpy as np

class Policy():
    def maker(self,n_R):
        F_lambda = np.random.randint(2, size=(n_R, n_R))
        for i in range(n_R):
            for j in range(n_R):
                F_lambda[i,j] = 1
        return F_lambda
