#include <stdio.h>

#define OFFSET_OF(obj, member) (int)((char*)&(obj).member - (char*)&(obj))

// Offset of a member inherited through `base`, measured from the start of obj.
#define OFFSET_VIA(base, obj, member) \
	(int)((char*)&((base*)&(obj))->member - (char*)&(obj))

class A
{
public:
	int m_a0;
	int m_a1;
};

class B : public A
{
public:
	int m_b0;
};

class C : public A
{
public:
	int m_c0;
};

class D : public B, public C
{
public:
	int m_d0;
};

int main()
{
	A a;
	B b;
	C c;
	D d;

	printf("A            size %d\n", (int)sizeof(A));
	printf("  A::m_a0    +%d\n", OFFSET_OF(a, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(a, m_a1));

	printf("B            size %d\n", (int)sizeof(B));
	printf("  A::m_a0    +%d\n", OFFSET_OF(b, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(b, m_a1));
	printf("  B::m_b0    +%d\n", OFFSET_OF(b, m_b0));

	printf("C            size %d\n", (int)sizeof(C));
	printf("  A::m_a0    +%d\n", OFFSET_OF(c, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(c, m_a1));
	printf("  C::m_c0    +%d\n", OFFSET_OF(c, m_c0));

	printf("D            size %d\n", (int)sizeof(D));
	printf("  B::A::m_a0 +%d\n", OFFSET_VIA(B, d, m_a0));
	printf("  B::A::m_a1 +%d\n", OFFSET_VIA(B, d, m_a1));
	printf("  B::m_b0    +%d\n", OFFSET_OF(d, m_b0));
	printf("  C::A::m_a0 +%d\n", OFFSET_VIA(C, d, m_a0));
	printf("  C::A::m_a1 +%d\n", OFFSET_VIA(C, d, m_a1));
	printf("  C::m_c0    +%d\n", OFFSET_OF(d, m_c0));
	printf("  D::m_d0    +%d\n", OFFSET_OF(d, m_d0));

	return 0;
}
