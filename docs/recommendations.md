# Recommendations

The following is a list of recommendations and best practices we have established at the [Lego Island Decompilation project](https://github.com/isledecomp/isle). They do not affect the output of `reccmp`, so it is up to you if you want to use them.

## Class/struct size annotation and assertion

Once we have a reasonable guess for the size of a class or struct, we add it in a comment like so:
```c++
// SIZE 0x1c
class MxCriticalSection {
public:
	MxCriticalSection();
	~MxCriticalSection();
	static void SetDoMutex();
    // ...
}
```
Furthermore, we use a compile-time assertion to verify that the recompiled size is correct (see also [this file](https://github.com/isledecomp/isle/blob/82453f62d84f979f8a6fc7b46e21b61cb835d2f1/util/decomp.h)):
```c++
#define DECOMP_STATIC_ASSERT(V)       \
	namespace                         \
	{                                 \
	typedef int foo[(V) ? 1 : -1];    \
	}
#define DECOMP_SIZE_ASSERT(T, S) DECOMP_STATIC_ASSERT(sizeof(T) == S)
```
Then we add `DECOMP_SIZE_ASSERT(MxCriticalSection, 0x1c)` to the respective `.cpp` file (if the class has no dedicated `.cpp` file, we use any appropriate `.cpp` file where the class is used).

## Member variables

We annotate member variables with their relative offsets.

```c++
class MxDSObject : public MxCore {
private:
	MxU32 m_sizeOnDisk;   // 0x08
	MxU16 m_type;         // 0x0c
	char* m_sourceName;   // 0x10
	undefined4 m_unk0x14; // 0x14
    // ...
}
```

## VTable members

In addition to the `VTABLE` annotation (which is relevant to `reccmp`), we also add comments to indicate the relative offset of each function:
```c++
// VTABLE: LEGO1 0x100dc900
class MxEventManager : public MxMediaManager {
public:
	MxEventManager();
	virtual ~MxEventManager() override;

	virtual void Destroy() override;                                     // vtable+0x18
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+0x28
    // ...
}
```

## Aliases for unknown scalar types

In order to distinguish known from unknown types, we have added the following typedefs:
```c++
typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
```
Note that the behaviour of signed and unsigned integers can be different even when no arithmetics is involved. If changing e.g. from `undefined4` to `int` improves the match, this is a strong indicator that the original variable was signed as well.