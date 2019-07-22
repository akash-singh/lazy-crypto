#include <cstdint>
#include <cstring>
#include <iostream>
#include <assert.h>
#include <cstdlib>
#include <iomanip>
#include <vector>

class bigInt {

public :
	std::vector<uint32_t> data;

	bigInt();
	bigInt(int);
	bigInt(int, int);
	bigInt(uint32_t [], int );
	~bigInt();
	
	void randInit();
	int realsize() const;
	int numBits() const;
	int numWords() const;
	bool  getSign() const;
	bool isZero () const ;
	void add (const bigInt &, bool) ;
	void signInvert ();
	void sub(const bigInt &, bool);
	bigInt mul(const bigInt &) const;
	bigInt mulPartial(const bigInt &, int num_words) const;
	bigInt expmod(const bigInt &exp, const bigInt &mod, bool) const;
	void bitAnd(const bigInt &);
	void rsh (int);
	uint32_t lsh(bool);
	bool getBit(int i) const;

	void mod (const bigInt &);
	bool isOdd () const;
	bool isEven () const;
	
	
};

std::ostream& operator<<(std::ostream& , const bigInt &);
bigInt operator+ (const bigInt &, const bigInt &);
bigInt operator- (const bigInt &, const bigInt &);
bigInt operator* (const bigInt &, const bigInt &);
bool operator == (const bigInt &, const bigInt &);
bool operator < (const bigInt &, const bigInt &);
bool operator > (const bigInt &, const bigInt &);
	
class montMult {
	public :
		montMult(const bigInt &m);
		void calcMontParams(const bigInt &m);
		void mmult(bigInt &c, const bigInt &a, const bigInt &b);
		void mred (bigInt &a);
		void zn2mont(bigInt &a);
		void mont2zn(bigInt &a);
		
	private:
		bigInt m, R, Rsquare, mprime, modRmask;
};

bigInt binEGCD_i (bigInt a, bigInt b, bigInt & x, bigInt & y);