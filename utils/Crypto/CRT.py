from Crypto.Util.number import GCD,Inverse

def CRT(items):
	#items is formated as an array of [(ai,ni),...]
	N = 1
	a = []
	n = []
	b = []
	binv = []
	for i in items:
		N*=i[1]
		a.append(i[0])
		n.append(i[1])
	for i in n:
		b.append(N//i)
		binv.append(inverse(b[-1],i))
	ans = 0
	for idx,i in enumerate(a):
		ans+=i*b[idx]*binv[idx]
		ans%=N
	return ans
