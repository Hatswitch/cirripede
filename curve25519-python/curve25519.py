

p = 2**255 - 19
A = 486662  

# order of the large subgroup of the curve
p1 = 2**252 + 27742317777372353535851937790883648493


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
    
    
def order(pt):
    """ Returns the order of a point on the curve.  Note that there are only
    a few choices since |E| = 8*p1 """
    
    for a in [1,2,4,8,p1,2*p1,4*p1,8*p1]:
        if times(pt,a) == infty:
            return a           

def orderp(pt):
    o = order(pt)
    if o < p1:
        return o
    else:
        return "%d*p1" % (o / p1)
            
    
if __name__ == '__main__':
    nine = point(9)                 
    print "9:", nine
    nine2 = times(nine,2)
    print "9*2:", nine2
    nine3 = times(nine,3)     
    print "9*3:", nine3
    nine5 = times(nine,5)  
    print "9*5:", nine5
    nine5p = add(nine2,nine3)
    print "9*2 + 9*3", nine5p
    assert add(nine2,nine3) == nine5     
    
    assert times(nine,p1) == infty   

    for i in range(1,100):
        if oncurve(i):
            print i, orderp(point(i))
