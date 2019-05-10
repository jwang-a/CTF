class CRT(object):
	def __init__(self,items):
		#items is formated as an array of [(ai,ni),...]
		self.N = 1
		self.a = []
		self.n = []
		self.b = []
		self.binv = []
		for i in items:
			self.N*=i[1]
			self.a.append(i[0])
			self.n.append(i[1])
		#extended CRT for non-coprime moduli
		#for idx,i in enumerate(self.n):
		#	gcd = self.gcd(self.N//i,i)
		#	if gcd!=1:
		#		self.a[idx]%=gcd
		#		self.n[idx]//=gcd
		#		self.N//=gcd
		for i in self.n:
			self.b.append(self.N//i)
			self.binv.append(self.findModInverse(self.b[-1],i))

	def gcd(self,a,b):
		while a!=0:
			a,b = b%a,a
		return b

	def findModInverse(self,a,m):
		if self.gcd(a,m)!=1:
			return None
		u1,u2,u3 = 1,0,a
		v1,v2,v3 = 0,1,m
		while v3!=0:
			q = u3//v3
			v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
		return u1%m

	def solve(self):
		self.ans = 0
		for idx,i in enumerate(self.a):
			self.ans+=i*self.b[idx]*self.binv[idx]
			self.ans%=self.N
		return self.ans
