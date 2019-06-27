class continued_fraction(object):
    def __init__(self):
        pass
    def calc(self,u,l,length):
        self.a = []
        self.u = u
        self.l = l
        for i in range(length):
            self.a.append(self.u//self.l)
            self.u%=self.l
            self.u,self.l = self.l,self.u
        return self.a
    def approximate(self,frac,length):
        self.k = []
        self.d = []
        for i in range(length):
            self.u = frac[i]
            self.l = 1
            for j in range(i,-1,-1):
                self.l,self.u = self.u,self.l
                if j!=0:
                    self.u = frac[j-1]*self.l+self.u
            self.k.append(self.u)
            self.d.append(self.l)
        return self.k,self.d

class weiners_attack(object):
    def __init__(self,n,e):
        self.n = n
        self.e = e
    def calc(self,length):
        self.CF = continued_fraction()
        self.frac = self.CF.calc(e,n,length)
        if self.frac[0]==0:
            self.frac = self.frac[1:]
        self.k,self.d = self.CF.approximate(self.frac,len(self.frac))
        import gmpy2
        for i in range(len(self.frac)):
            if self.k[i]!=0 and (self.e*self.d[i]-1)%self.k[i]==0:
                phi = (self.e*self.d[i]-1)//self.k[i]
                s = self.n-phi+1
                discr = s*s-4*self.n
                if discr>=0:
                    t = gmpy2.iroot(discr,2)
                    if t[1] is True and (s+t[0])%2==0:
                        return self.d[i]
        return None
