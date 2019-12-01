#ifndef __HOOK_H__
#define __HOOK_H__

extern void hookModuleDestroy(void);
extern int hookModuleInit(void);

typedef struct __HOOK_STUB
{
	void ** orgFun;
	unsigned char * fakeFun;
	char fnName[64];
	// -- unsigned char * _raw;
	// -- unsigned char * _code;
	// -- void * _origPtr; // -- the function hooked;
}HOOK_STUB;

int hookStubSetEx(HOOK_STUB * stub, void * hook, void ** ppTgtFunction);
void hookStubDestroy(HOOK_STUB * stub);
int hookStubInitialize(HOOK_STUB * stub, const char * name);
int hookStubOffset(HOOK_STUB * stub, void * hook, void ** ppTgtFunction, unsigned int offset);

	 
#endif
