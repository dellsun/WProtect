#ifdef  __GNUC__
#define WProtectBegin() __asm__(".byte 0xEB\n\t.byte 0xf\n\t.string \"WProtect Begin\"\n\t");   
#define WProtectEnd() __asm__(".byte 0xEB\n\t.byte 0xd\n\t.string \"WProtect End\"\n\t"); 
#endif

#ifdef _MSC_VER
// 	0xEB, 0x0F, 0x57, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x20, 0x42, 0x65, 0x67, 0x69, 0x6E, 0x00
#define WProtectBegin() __asm _emit 0xEB \
	__asm _emit 0x0F \
	__asm _emit 0x57 \
	__asm _emit 0x50 \
	__asm _emit 0x72 \
	__asm _emit 0x6F \
	__asm _emit 0x74 \
	__asm _emit 0x65 \
	__asm _emit 0x63 \
	__asm _emit 0x74 \
	__asm _emit 0x20 \
	__asm _emit 0x42 \
	__asm _emit 0x65 \
	__asm _emit 0x67 \
	__asm _emit 0x69 \
	__asm _emit 0x6E \
	__asm _emit 0x00
//0xEB, 0x0D, 0x57, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x20, 0x45, 0x6E, 0x64, 0x00
#define WProtectEnd() __asm _emit 0xEB \
	__asm _emit 0x0D \
	__asm _emit 0x57 \
	__asm _emit 0x50 \
	__asm _emit 0x72 \
	__asm _emit 0x6F \
	__asm _emit 0x74 \
	__asm _emit 0x65 \
	__asm _emit 0x63 \
	__asm _emit 0x74 \
	__asm _emit 0x20 \
	__asm _emit 0x45 \
	__asm _emit 0x6E \
	__asm _emit 0x64 \
	__asm _emit 0x00

#endif
