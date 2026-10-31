#include <stdio.h>

#define OFFSET_OF(obj, member) (int)((char*)&(obj).member - (char*)&(obj))

class A
{
public:
	double m_a0;
};

class B
{
public:
	char m_b0;
};

class C : public virtual A, public virtual B
{
public:
	double m_c0;
};

class D : public virtual B, public virtual A
{
public:
	double m_d0;
};

int main()
{
	A a;
	B b;
	C c;
	D d;

	printf("A            size %d\n", (int)sizeof(A));
	printf("  A::m_a0    +%d\n", OFFSET_OF(a, m_a0));

	printf("B            size %d\n", (int)sizeof(B));
	printf("  B::m_b0    +%d\n", OFFSET_OF(b, m_b0));

	printf("C            size %d\n", (int)sizeof(C));
	printf("  C::m_c0    +%d\n", OFFSET_OF(c, m_c0));
	printf("  A::m_a0    +%d\n", OFFSET_OF(c, m_a0));
	printf("  B::m_b0    +%d\n", OFFSET_OF(c, m_b0));

	printf("D            size %d\n", (int)sizeof(D));
	printf("  D::m_d0    +%d\n", OFFSET_OF(d, m_d0));
	printf("  B::m_b0    +%d\n", OFFSET_OF(d, m_b0));
	printf("  A::m_a0    +%d\n", OFFSET_OF(d, m_a0));

	return 0;
}
