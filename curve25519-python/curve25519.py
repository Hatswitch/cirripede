p = 2**255 - 19
A = 486662  

class Fp: 
    p = 2**255 - 19
    def __init__(self,x):  
        if isinstance(x,Fp):
            self.x = x.x
        else:
            self.x = x % self.p
    
    def __add__(self,o):   
        return Fp(self.x + o.x)
        
    def __sub__(self,o):
        return Fp(self.x - o.x)          
        
    def __mul__(self,o):
        return Fp(self.x * o.x)
        
    def __pow__(self,other):  # other must be an integer
        return Fp(pow(self.x,other.x,self.p))
    
    def __div__(self,other):
        return Fp((self.x) * other.inverse().x)   
        
    def inverse(self):
        assert self.x != 0
        return Fp(pow(self.x,self.p-2,self.p))
        
    def __eq__(self,other):
        return self.x == Fp(other).x     
        
    def __rmul__(self,other):
        return self.__mul__(other)   
        
    def __coerce__(self, other):
        return (self,Fp(other))      
        
    def __repr__(self):
        return "(%d %% 2**255 - 19)" % self.x       
        
    def __neg__(self):
        return Fp(-self.x)
        
    def isqr(self):
        return self.x == 0 or pow(self.x,(self.p-1)/2,self.p) == 1
        
    def sqrt(self):                      
        assert self.isqr()
        return Fp(modular_sqrt(self.x,self.p))      
        
    def __nonzero__(self):
        return self.x != 0 
        
        
    def __long__(self):
        return self.x
        
class Fp2:  # extension field    
    p = Fp.p       
    b = 2       # non-qr, extension field is F_p[sqrt(b)]              
    
    def __init__(self, x, y=0):
        if isinstance(x, Fp2):
            self.x = x.x
            self.y = x.y    
        elif type(x) == tuple:
            self.x = Fp(x[0])
            self.y = Fp(x[1])
        else:           
            self.x = Fp(x)       
            self.y = Fp(y)
        
    def __coerce__(self,other):
        return (self,Fp2(other))
        
    def __add__(self,other):
        return Fp2(self.x+other.x, self.y + other.y)
        
    def __sub__(self,other):
        return Fp2(self.x - other.x, self.y - other.y)
        
    def __mul__(self,other):
        return Fp2(self.x*other.x + self.y*other.y * self.b, self.x*other.y + self.y*other.x)
        
    def inverse(self):                               
        den = self.x**2 - self.y**2 * self.b
        return Fp2(self.x / den, - self.y / den)   
        
    def __div__(self,other):
        return self * other.inverse()        
        
    def __eq__(self,other):    
        try:
            other = Fp2(other)    
            return self.x == other.x and self.y == other.y
        except TypeError:                                
            return False
        
    def __pow__(self,other):    
        if isinstance(other,Fp2):
            assert other.y == 0
            power = long(other.x)
        elif isinstance(other,Fp):
            power = long(other.x)
        else:
            power = long(other)

        if power == 0:
            return Fp2(1)
        elif power == 1:
            return self    
        elif not self:
            return self # 0 to any non-zero power is 0
            
        x = self.__pow__(power/2)
        if power % 2 == 1:
            return x * x * self
        else:
            return x * x     
            
    def __nonzero__(self):
        return bool(self.x) or bool(self.y)
            
    def __repr__(self):
        if self.y:
            return "(%d + %d sqrt(%d) %% 2**255 - 19)" % (self.x,self.y,self.b)
        else:
            return repr(self.x)   
            
    def __rmul__(self,other):
        return self.__mul__(Fp2(other))     
            
    def sqrt(self):
        assert self.y == 0  # for now, don't take square roots of sqrt(b)
        
        if self.x.isqr():
            return Fp2(self.x.sqrt())
        else:
            return Fp2(0, (self.x/self.b).sqrt())  
            
class Curve:
    A = Fp2(486662)         
    
    def __init__(self, x=None, y=None):
        if x == None:
            self.isinfty = True
        else:     
            self.isinfty = False   
            self.x = Fp2(x)         
            if y:
                self.y = Fp2(y)
            else:
                self.y = self.curve().sqrt()       
                
            
    def curve(self):
        return self.x ** 3 + self.A * self.x ** 2 + self.x      
        
    def double(self):  
        if self.isinfty:
            return self
        if self.x == 0:
            return Curve()    
        l = (3* self.x**2 + 2 * self.A  * self.x + 1) / (2*self.y)
        xx = l**2 - self.A - 2 * self.x
        yy = l * (self.x-xx) - self.y       
     #   print "%s + %s = Curve(%s,%s)" % (self,self,xx,yy)
        return Curve(xx,yy) 
 
    def __add__(self,other):
        if self.isinfty:
            return other
        elif other.isinfty:
            return self  
        if self.x == other.x:
            if self.y == other.y:
                return self.double()
            else:
                assert self.y + other.y == 0
                return Curve()   
                
        l = (other.y - self.y) / (other.x - self.x)
        xxx = l**2 - self.A - self.x - other.x
        yyy = l * (self.x-xxx) - self.y
        return Curve(xxx,yyy)   
        
    def __repr__(self):
        if self.isinfty:
            return "infty"
        else:
            return "[%s,%s]" % (self.x,self.y)      
            
    def __mul__(self, other):    
        if self.isinfty:
            return self
            
        n = long(other)
        if n == 0:
            return Curve()
        elif n == 1:
            return self
        else:  
            sq = self.__mul__(n/2).double()
            if n % 2 == 1:
                return sq + self
            else:
                return sq    

    def __eq__(self,other):    
        
        if self.isinfty and other.isinfty: 
            return True
        if self.isinfty or other.isinfty:
            return False
        return self.x == other.x and self.y == other.y   
        
    def order(self):
        """ Returns the order of a point on the curve.  Note that there are only
        a few choices since |E| = 8*p1 """     
        
        if self.y.y:
            # we're on the twist
            orders = [1,2,4,p2,p2*2,p2*4]
        else:
            orders = [1,2,4,8,p1,2*p1,4*p1,8*p1]
        for a in orders:
            if  (self*a).isinfty:
                return a      
                
    def orderp(self):
        o = self.order()

        if o <= 8:
            return o
        elif o % p1 == 0:
            return "%d*p1" % (o / p1)
        else:
            assert o % p2 == 0
            return "%d*p2" % (o / p2)
     

            
        

# order of the large subgroup of the curve
p1 = 2**252 + 27742317777372353535851937790883648493         
p2 = 2**253 - 55484635554744707071703875581767296995

def curve(x): 
    return x**3 + A * x**2 + x
    


def curve(x):
    return (x**3 + A * x**2 + x) % p 
    
def point(x):
    return (x,modular_sqrt(curve(x),p))
    
def isqr(x):         
    return x == 0 or pow(x, (p-1)/2, p) == 1

def oncurve(x):
    return isqr(curve(x))                     
    
def inverse(x):     
    assert x != 0
    return pow(x,p-2,p)
    
infty = (-1,-1)
                     
def double(pt): 
    if pt == infty or pt == (0,0):
        return infty       
    (x,y) = pt
    assert y != 0
    l = ((3* x**2 + 2 * A * x + 1) * inverse(2*y)) % p
    xx = (l**2 - A - 2*x) % p
    yy = (l*(x-xx) - y) % p
    return (xx,yy)     

def add(pt,q):
    if pt == infty:
        return q
    elif q == infty:
        return pt
    (x,y) = pt
    (xx,yy) = q
    if x == xx:
        if y == yy:
            return double(pt)
        else:           
            assert (y + yy) % p == 0
            return infty   
            
    l = ((yy-y) * inverse(xx-x)) % p
    xxx = (l**2 - A - x - xx) % p
    yyy = (l *(x-xxx) - y) % p
    return (xxx,yyy)
            
def times(pt,n):
    if n == 0:
        return infty
    elif n == 1:
        return pt
    else:
        sq = double(times(pt,n/2))
        if n % 2 == 1:
            return add(sq,pt)
        else:
            return sq

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return n
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls  
    
    

def orderp(pt):
    o = order(pt)
    if o < p1:
        return o
    else:
        return "%d*p1" % (o / p1)
            
    
if __name__ == '__main__':
    nine = Curve(9)                 
    print "9:", nine    
    print point(9)
    nine2 = nine * 2
    print "9*2:", nine2
    nine3 = nine * 3
    print "9*3:", nine3
    nine5 = nine * 5
    print "9*5:", nine5
    nine5p = nine2 + nine3
    print "9*2 + 9*3", nine5p
    assert nine5p == nine5         
    
    assert (nine * p1).isinfty
    
#    assert times(nine,p1) == infty       
    
    print Fp2(9) ** 3

    for i in range(1,100):  
        print i, Curve(i).orderp()
