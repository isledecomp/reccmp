#include <stdio.h>

#define OFFSET_OF(obj, member) (int)((char*)&(obj).member - (char*)&(obj))

class A
{
public:
	int m_a0;
	int m_a1;
};

class B : public virtual A
{
public:
	virtual void Update();
	int m_b0;
};

class C : public B
{
public:
	int m_c0;
};

void B::Update()
{
	m_b0 = 0;
}

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
	printf("  A::m_a0    +%d\n", OFFSET_OF(b, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(b, m_a1));

	printf("C            size %d\n", (int)sizeof(C));
	printf("  C::m_c0    +%d\n", OFFSET_OF(c, m_c0));
	printf("  B::m_b0    +%d\n", OFFSET_OF(c, m_b0));
	printf("  A::m_a0    +%d\n", OFFSET_OF(c, m_a0));
	printf("  A::m_a1    +%d\n", OFFSET_OF(c, m_a1));

	c.Update();

	return 0;
}
