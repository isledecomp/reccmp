#ifndef MXUTIL_H
#define MXUTIL_H

#include "mxtypes.h"

#include <string.h>

class MxDSFile;
class MxDSObject;

template <class T>
inline T Abs(T p_t)
{
	return p_t < 0 ? -p_t : p_t;
}

template <class T>
inline T Min(T p_t1, T p_t2)
{
	return p_t1 < p_t2 ? p_t1 : p_t2;
}

template <class T>
inline T Max(T p_t1, T p_t2)
{
	return p_t1 > p_t2 ? p_t1 : p_t2;
}

template <class T>
inline void GetScalar(MxU8** p_source, T& p_dest)
{
	p_dest = *(T*) *p_source;
	*p_source += sizeof(T);
}

template <class T>
inline T GetScalar(T** p_source)
{
	T val = **p_source;
	*p_source += 1;
	return val;
}

template <class T>
inline void GetDouble(MxU8** p_source, T& p_dest)
{
	p_dest = *(double*) *p_source;
	*p_source += sizeof(double);
}

template <class T>
inline void GetString(MxU8** p_source, char** p_dest, T* p_obj, void (T::*p_setter)(const char*))
{
	(p_obj->*p_setter)((char*) *p_source);
	*p_source += strlen(*p_dest) + 1;
}

MxBool FUN_100b6e10(
	MxS32 p_bitmapWidth,
	MxS32 p_bitmapHeight,
	MxS32 p_videoParamWidth,
	MxS32 p_videoParamHeight,
	MxS32* p_left,
	MxS32* p_top,
	MxS32* p_right,
	MxS32* p_bottom,
	MxS32* p_width,
	MxS32* p_height
);

__declspec(dllexport) void MakeSourceName(char*, const char*);
__declspec(dllexport) void SetOmniUserMessage(void (*)(const char*, int));
__declspec(dllexport) MxDSObject* CreateStreamObject(MxDSFile*, MxS16);

MxBool KeyValueStringParse(char*, const char*, const char*);

#endif // MXUTIL_H
