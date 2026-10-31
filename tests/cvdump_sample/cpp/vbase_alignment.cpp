#include <stdio.h>

#define OFFSET_OF(obj, member) (int)((char*)&(obj).member - (char*)&(obj))

class A
{
public:
	double m_a0;
	char m_a1;
};

class B : public virtual A
{
public:
	int m_b0;
	char m_b1;
};

class C : public B
{
public:
	char m_c0;
};

int main()
{
	A a;
	B b;
	C c;

	printf("A            size %d\n", (int)sizeof(A));
	printf("  A::m_a0    +%d\n", OFFSET_OF(a, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(a, m_a1));

	printf("B            size %d\n", (int)sizeof(B));
	printf("  B::m_b0    +%d\n", OFFSET_OF(b, m_b0));
	printf("  B::m_b1    +%d\n", OFFSET_OF(b, m_b1));
	printf("  A::m_a0    +%d\n", OFFSET_OF(b, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(b, m_a1));

	printf("C            size %d\n", (int)sizeof(C));
	printf("  B::m_b0    +%d\n", OFFSET_OF(c, m_b0));
	printf("  B::m_b1    +%d\n", OFFSET_OF(c, m_b1));
	printf("  C::m_c0    +%d\n", OFFSET_OF(c, m_c0));
	printf("  A::m_a0    +%d\n", OFFSET_OF(c, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(c, m_a1));

	return 0;
}
