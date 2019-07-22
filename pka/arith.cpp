
#include <arith.h>

// Constructor - Initialize with a integer val
bigInt::bigInt() {
}

// Initialize size words with 0
bigInt::bigInt(int size) {
	data.resize(size,0);
}

// Initialize size words with val
bigInt::bigInt(int size, int val) {
	data.resize(size,val);
}

// Constructor - Initialize with array
bigInt::bigInt(uint32_t val[], int size) {
	data.resize(size,0);
	if(val != nullptr) {
		for(int i=0; i<size; i++)
			data[i] = val[i];
	}
}

// Empty destructor
bigInt::~bigInt() {
}

// Randomize data
void bigInt::randInit() {
	for( auto &i : data) {
		i = rand();
	}
}

// Actual size used up by the underlying data
int bigInt::numWords() const {
	int sz = 0;
	for(auto i= data.end()-1; i>=data.begin(); i--) {
		if((!getSign() && *i != 0) || (getSign() && *i != 0xFFFFFFFF)) 
			break;
		else
			sz++;
	}
	return data.size() - sz;
}

int bigInt::numBits() const {
	int size_in_words = numWords();
	uint32_t last_word = data[numWords()-1];
	int i = 31;
	while((last_word & (0x1 << i)) == getSign())
		i--;
	
	return ((size_in_words-1)*32 + i + 1);
		
}

// In place addition and subtraction - Time complexity O(size)
// auto_upsize == true prevents overflow
void bigInt::add (const bigInt &x, bool auto_upsize = true) {
	
	if(auto_upsize) {
		int result_size = std::max(numWords(), x.numWords());
	
		if(data.size() < result_size)
			data.resize(result_size,(getSign() ? 0xFFFFFFFF : 0));
	}
	
	uint32_t carry = 0;
	bool overflow_possible = (x.getSign() == getSign());
	
	for(int i=0; i<data.size(); i++) {
		uint32_t op2 = i < x.numWords() ? x.data[i] : (x.getSign() ? 0xFFFFFFFF : 0);
		
		data[i] += op2;
		uint32_t carry_1 = data[i] < op2;
		data[i] += carry;
		uint32_t carry_2 = data[i] < carry;
		carry = carry_1 | carry_2;
	}
	
	 
	if(overflow_possible && (getSign() != x.getSign()) && auto_upsize) {
		carry = carry ? 0xFFFFFFFF : 0;
		data.push_back(carry);
	}
}

void bigInt::sub (const bigInt &x, bool auto_upsize = true) {
	bigInt temp = x;
	temp.signInvert();
	add(temp,auto_upsize);
}

// Old school multiplication - Time complexity O(size^2)
// Output is sized to accomodate result
bigInt bigInt::mul (const bigInt &x) const {
	
	bigInt xx = *this, yy = x;

	bool invert_result = false;
	
	if(xx.getSign()) {
		xx.signInvert();
		invert_result = ~invert_result;
	}
	
	if(yy.getSign()) {
		yy.signInvert();
		invert_result = ~invert_result;
	}
	
	bigInt res(xx.numWords() + yy.numWords()+1);
	
	for(int i=0; i<xx.numWords(); i++) {
		uint32_t carry = 0;
		for(int j=0; j<yy.numWords(); j++) {
			uint64_t temp = (uint64_t) xx.data[i] * (uint64_t) yy.data[j];
			temp += res.data[i+j];
			temp += carry;
			res.data[i+j] = temp;
			carry = temp >> 32;
		}
		res.data[yy.numWords()+i] = carry;
	}
	
	if(invert_result)
		res.signInvert();
	
	return res;
}

// Partial Multiplication - only num_words of output are calculated
// Comes in handy for modular multiplication, i/o treated as unsigned numbers
// Time complexity - O(num_words^2)
bigInt bigInt::mulPartial (const bigInt &x, int num_words) const {
	
	bigInt res(num_words);
	
	for(int i=0; i<x.numWords(); i++) {
		uint32_t carry = 0;
		for(int j=0; j<numWords(); j++) {
			if(i+j >= num_words)
				continue;
			
			uint64_t temp = (uint64_t) x.data[i] * (uint64_t) data[j];
			temp += res.data[i+j];
			temp += carry;
			res.data[i+j] = temp;
			carry = temp >> 32;
		}
	}
	return res;
}

// Modular exponentiation using Montgomery multiplication
// Old school multiplication is also supported 
bigInt bigInt::expmod (const bigInt &exp, const bigInt &mod, bool useMont = true)  const {
	
	if (useMont == false) {
		bigInt acc(1,1);
		bigInt x(*this);
		for(int i=0; i<exp.numBits(); i++) {
			if(exp.getBit(i)) {
				acc = acc*x;
				acc.mod(mod);
			}
			
			x = x * x;
			x.mod(mod);
		}
		
		return acc;
	}
	
	montMult mm(mod);
	bigInt x (*this);
	mm.zn2mont(x);
	bigInt acc(1,1);
	mm.zn2mont(acc);
	
	for(int i=0; i<exp.numBits(); i++) {
		if(exp.getBit(i))
			mm.mmult(acc, acc, x);
		
		mm.mmult(x,x,x);
	}
	mm.mont2zn(acc);
	return acc;
}

// Bitwise AND
void bigInt::bitAnd (const bigInt &x) {
	
	for(int i=0; i<data.size(); i++) {
		uint32_t op2 = i < x.numWords() ? x.data[i] : (x.getSign() ? 0xFFFFFFFF : 0);
		
		data[i] &= op2;
	}

}

bool bigInt::getBit(int i) const {
	int word = i/32;
	int bit = i%32;
	
	return (data[word] & (1 << bit));
}

// Calc Two's complement (in place)
void bigInt::signInvert () {
	for(auto &i : data)
		i = ~i;
	
	uint32_t temp[] = {1};
	bigInt One(temp,1);
	add(One);
}

// Right/Left shift
// auto_upsize == true prevents overflow
void bigInt::rsh (int i=1) {
	
	int num_words = i / 32;
	int num_bits = i % 32;
	
	if(num_words > 0)
		data.erase(data.begin(), data.begin()+num_words);
	
	uint32_t ov = (getSign() & 0x1) << 31;

	for(auto i=data.end()-1; i>=data.begin(); i--) {
		uint32_t ov_nxt = (*i << (32-num_bits));	
		*i >>= num_bits;
		*i |= ov;
		ov = ov_nxt;
	}

}

uint32_t bigInt::lsh(bool auto_upsize = false) {
	if(auto_upsize && ((data.back() & 0x80000000) != (data.back() & 0x40000000)) )
		data.push_back(getSign() ? 0xFFFFFFFF : 0);
		
	uint32_t ov = 0;
		
	for(auto &i: data){
		uint32_t ov_nxt = (i & (1 << 31) ) >> 31;
		i <<= 1;
		i |= ov;
		ov = ov_nxt;
	}
	return ov;
}

// Modulo reduction, time complexity O(size^3)
void bigInt::mod (const bigInt &N) {
	bigInt div = N;
	while(!(*this < N)) {
		uint32_t ov;
		while(!(*this < div))
			div.lsh(true);
		
		div.rsh();
		sub(div);
		div = N;
	}
	
	data.resize(N.numWords());
}

// Returns sign - true = -ve , false = +ve
bool bigInt::getSign() const {
	return (data.back() & 0x80000000);
}

bool bigInt::isZero () const {
	for(auto i: data) {
		if(i != 0)
			return false;
	}
	return true;
}

bool bigInt::isOdd () const {
	return data[0] & 0x1;
}

bool bigInt::isEven () const {
	return !isOdd();
}

/**********************************************************************

	Overloading common opearators for bigInt

***********************************************************************/

bigInt operator+ (const bigInt & op1, const bigInt & op2) {
	bigInt result = op1;
	result.add(op2);
	return result;
}


bigInt operator- (const bigInt & op1, const bigInt & op2) {
	bigInt result = op1;
	result.sub(op2);
	return result;
}

bigInt operator* (const bigInt &x, const bigInt &y ) {
	return x.mul(y);
}

bool operator == (const bigInt & lhs, const bigInt & rhs) {
	int rsize = rhs.data.size();
	int lsize = lhs.data.size();
	
	if(lhs.getSign() != rhs.getSign())
		return false;
	
	for(int i=0;i<std::max(lsize,rsize);i++) {
		uint32_t l = i < lsize ? lhs.data[i] : (lhs.getSign() ? 0xFFFFFFFF : 0);
		uint32_t r = i < rsize ? rhs.data[i] : (rhs.getSign() ? 0xFFFFFFFF : 0);
		
		if(l != r)
			return false;
	}
	
	return true;
}

bool operator < (const bigInt & lhs, const bigInt & rhs) {
	
	int rsize = rhs.data.size();
	int lsize = lhs.data.size();
	
	if(lhs.getSign() && !rhs.getSign())
		return true;
	else if(!lhs.getSign() && rhs.getSign())
		return false;
	
	for(int i=std::max(lsize,rsize)-1;i>=0;i--) {
		uint32_t l = i < lsize ? lhs.data[i] : (lhs.getSign() ? 0xFFFFFFFF : 0);
		uint32_t r = i < rsize ? rhs.data[i] : (rhs.getSign() ? 0xFFFFFFFF : 0);
		
		if(l < r)
			return true;
		else if (l > r)
			return false;
	}
	
	return false;
}

bool operator > (const bigInt & lhs, const bigInt & rhs) {
	
	int rsize = rhs.data.size();
	int lsize = lhs.data.size();
	
	if(lhs.getSign() && !rhs.getSign())
		return false;
	else if(!lhs.getSign() && rhs.getSign())
		return true;
	
	for(int i=std::max(lsize,rsize)-1;i>=0;i--) {
		uint32_t l = i < lsize ? lhs.data[i] : (lhs.getSign() ? 0xFFFFFFFF : 0);
		uint32_t r = i < rsize ? rhs.data[i] : (rhs.getSign() ? 0xFFFFFFFF : 0);
		
		if(l > r)
			return true;
		else if (l < r)
			return false;
	}
	
	return false;
}

std::ostream& operator<<(std::ostream& os, const bigInt &rhs) {

	bigInt temp(rhs);
	
	if(rhs.getSign()) {
		os << "-";
		temp.signInvert();
	} else {
		os << " ";
	}	
	
	os << "0x";
	for(int i=temp.data.size()-1; i >= 0; i--)
			os << std::hex << std::setfill('0') << std::setw(8) << temp.data[i];

	return os;
}


/****************************************************************************************************************
Euclidean Algorithm - 
	GCD(a,b) = GCD(b,a%b)
	
Extended Euclidean algorithm calculates Bezout's coeffs along with
the GCD such that
	g = ax + by, g = gcd(a,b)
	
Binary version of Extended Euclidean Algorithm avoids costly mod calculations
by using subtraction and bit shifts.

We start with 2 values r0 and r1 set to a and b

r0 = a
r1 = b

1.	if r0 and r1 are both even GCD(r0,r1) = 2* gcd(r0/2,r1/2) 
	remove all common powers of 2 from a and b
   
2.  if only one of r0 and r1 is even (let's say r0)
	then GCD(r0,r1) = GCD(r0/2,r1)
	
3.  if both r0 and r1 are odd, we subtract. It can be shown that
	GCD(r0,r1) = GCD(r0-r1,r1), r0 > r1
	
4.  Once we get either r0 or r1 as zero, other one is GCD

This was the easy part, calculating Bezout's coeffs is little tricky. We start with set of
numbers such that

	r0 = ax0 + by0
	r1 = ax1 + by1

and keep track of these as we go through the series of transformation.

Following values of x0,y0 x1,y1 satisfy our initial conditions

	x0 = 1, y0 = 0
	x1 = 0, y1 = 1
	
	r0 = a = a.1 + b.0
	r1 = b = a.0 + b.1
	
Now we need to figure out how these values change as we go through our algorithm.

For case #1 where we remove common factor of 2
	g = ax + by
	g/2 = a/2*x + b/2*y
	
	=> coeffs do not change 
	
For case #3 where we transform r0 = r0-r1 (or the other way if r1>r0), we have
	r0 = ax0 + by0
	r1 = ax1 + by1
	
	r0-r1 = a(x0-x1) + b(y0-y1)
	
	thus, x0 = x0-x1, y0 = y0-y1
	
For case #2 where we r0 - r0/2 (or r1 = r1/2 depending upon which one is even), the obvious
solution becomes
	r0 = ax0 + by0
	r0/1 = ax0/2 + by0/2
	
But this works only when both x0 and y0 are even, if either of them is not we have to come up with 
alternative transformation. We chose following - 
	x0 = (x0 - b)/2, y0 = (y0 + a)/2
	=> ax0 + by0 = a (x0 - b)/2 + b (y0 + a)/2
				 = ax0 / 2 + by0/2 - ab/2 + ab/2
				 = ax0/2 + by0/2
				 = r0/2
				 
	x0 = (x0 - b)/2, y0 = (y0 + a)/2

Only thing remaining is to prove that (x0-b) and (y0+a) are both even. Now we know that -
	1. atleast one of the x0,y0 is odd
	2. a and b cannot be simultaneously even as we have already removed common factors of 2
	
This leaves us with following comb -
	-	x0 - odd, y0 - even
		r0 = ax0 + by0 was even, by0  is even => ax0 is even => a is even => b is odd
		=> x0 odd, y0 even, a even, b odd
		=> x0-b = even, y0+a = even
		
	-	similar argument when x0 is even, y0 is odd
	
	-  	x0 - odd, y0 - odd
		r0 = ax0 + by0  was odd => both a and b are odd
		=> x0-b = even, y0+a = even

**************************************************************************************************************************/
	
bigInt binEGCD_i (bigInt a, bigInt b, bigInt & x, bigInt & y) {
	uint32_t t0[] = {0};
	uint32_t t1[] = {1};
	
	bigInt r0(a), r1(b), x0(t1,1), y0(t0,1), x1(t0,1), y1(t1,1), g;
	int gshift = 0;
	while(r0.isEven() && r1.isEven()) {
		r0.rsh();
		r1.rsh();
		gshift++;
	} 
	
	bigInt a_red = r0, b_red = r1;

	int cnt = 0;
	while(!r1.isZero() && !r0.isZero()) {
		
	#ifdef DEBUG_EGCD
		std::cout << std::endl;
		std::cout << "r0 = " << r0 << "; x0 = " << x0 << "; y0 = " << y0 << std::endl;
		std::cout << "r1 = " << r1 << "; x1 = " << x1 << "; y1 = " << y1 << std::endl;
		std::cout << "ax0+by0 = " << (x0*a_red + y0*b_red) << std::endl;
		std::cout << "ax1+by1 = " << (x1*a_red + y1*b_red) << std::endl;
		assert(x0*a_red + y0*b_red == r0);
		assert(x1*a_red + y1*b_red == r1);
	#endif
	
		if(!r0.isEven() && !r1.isEven()) {
			if (r1 < r0) {
				r0.sub(r1);
				x0.sub(x1);
				y0.sub(y1);
			} else {
				r1.sub(r0);
				x1.sub(x0);
				y1.sub(y0);
			}
		} else if (r0.isEven()) {
		
			r0.rsh();
			if(x0.isEven() && y0.isEven()) {
				x0.rsh();
				y0.rsh();
			} else {

				x0.add(b_red);
				y0.sub(a_red);
				x0.rsh();
				y0.rsh();
			}
		} else {
			assert(r1.isEven());
			r1.rsh();
			if(x1.isEven() && y1.isEven()) {
				x1.rsh();
				y1.rsh();
			} else {
				x1.add(b_red);
				y1.sub(a_red);
				x1.rsh();
				y1.rsh();
			}
		}
	}
		
	if(r0.isZero()) {
		g = r1;
		x = x1;
		y = y1;
	} else {
		g = r0;
		x = x0;
		y = y0;
	}
	
	for(int i=0;i<gshift;i++)
		g.lsh();
		
	return g;
}

/**************************************************************************************************************************

Montgomery Multiplication algorithm speeds up modular multiplication by avoiding costly modulo operation. This is achieved
by transforming data into Montgomery domain where modulo is calculated over 2^n.

Given: a,b, modulus M
calc:	a*b mod M

First we select, smallest R = 2^n : R > M
Conversion into Mont domain is defined as a' = a*R mod M. So,

a' = aR mod M
b' = bR mod M

Now, a'*b* = aR * bR = abR.R. We need c' = a'b'R. So we need an algorithm to effeciently divide by R mod M.
This is called Montgomery reduction.

Montgomery reduction -
Given: C, R, M
calc:  C / R mod M

This division will be effecient if C had zeros in the LSB. To achive this we'll add something to C such that

	C = C + M*t = 0 mod R (Note that C + Mt  = C mod M, C remains unchanged mod M)
=>	t = -C/M mod R = C * -1/M mod R

	-1/M mod R is pre calculated using Extende Euclidean algorithm and is called mprime.
	
	So, t = c*mprime mod R
	
	Thus our reduction algorithm becomes - 
	C = C + m*t, t=c*mprime mod R
	This gives C which is 0 mod R, thus C/R = right shift by number of zeros in R ( R is of form 1000000..)
	
	Now, that we have a effecient algo for Montgomery reduction (mred), we can define multiplication algo as - 
	
	MMult(a',b') = mred(a' * b')
	
	For entering into Montgomery domain, we need a' = a.R mod M = MMult(a,R^2) {R^2 mod M is pre calculated }
	Similarly for leaving Montgomery domain, we need a = a'/R mod M = mred(a')
	
	This is not really helpful as entering and exiting from Montgomery domain is constly, but it helps in exponentiation
	as we have to enter and exit Montgomery domain only once.
**************************************************************************************************************************/

montMult::montMult(const bigInt &m) {
	calcMontParams(m);
}
		
void montMult::calcMontParams (const bigInt &m) {
	
	if(m.isEven()) {
		std::cout << "Modulus cannot be even for montgomery multiplication" << std::endl;
		std::exit(1);
	}
	
	this->m = m;
	
	R.data.resize(m.numWords(),0);
	R.data[m.numWords()-1] = 0x1;
	
	//R.lsh(m.numBits()-1);
	while(R < m)
		R.lsh(true);
	
	bigInt Rprime, g;
	
	g = binEGCD_i(R,m,Rprime,mprime);
	mprime.signInvert();
	
	Rsquare = R*R;
	Rsquare.mod(m);
	bigInt one(1,1);
	modRmask = R - one;
	
	#ifdef DEBUG_MONT
	std::cout << "M = " << m << std::endl;
	std::cout << "R = " << R << std::endl;
	std::cout << "Mp= " << mprime << std::endl;
	std::cout << "R2= " << Rsquare << std::endl;
	#endif
	
}

void montMult::mred ( bigInt &a) {

	// t = a * mprime (mod R);
	bigInt t = a.mulPartial(mprime,R.numWords());
	t.bitAnd(modRmask);
	
 	a = a + (m * t);
	a.rsh(R.numBits()-1);
	
	if(!(a < m))
		a.sub(m);
}

void montMult::mmult (bigInt &c, const bigInt &a, const bigInt &b) {
	c = a*b;
	mred(c);

}

void montMult::zn2mont (bigInt &a) {
	mmult(a,a,Rsquare);
}

void montMult::mont2zn (bigInt &a) {
	mred(a);
}