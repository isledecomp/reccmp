#include <stdio.h>

#define OFFSET_OF(obj, member) (int)((char*)&(obj).member - (char*)&(obj))

class A
{
public:
	int m_a0;
	int m_a1;
};

class B
{
public:
	int m_b0;
};

class C : public virtual A, public virtual B
{
public:
	int m_c0;
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

	printf("C            size %d\n", (int)sizeof(C));
	printf("  C::m_c0    +%d\n", OFFSET_OF(c, m_c0));
	printf("  A::m_a0    +%d\n", OFFSET_OF(c, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(c, m_a1));
	printf("  B::m_b0    +%d\n", OFFSET_OF(c, m_b0));

	return 0;
}
