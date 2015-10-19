set(LIB_AsmJit
	opcode_table.cpp
	AssemblerX86X64.cpp
	CodeGenerator.cpp
	Compiler.cpp
	CompilerX86X64.cpp
	CpuInfo.cpp
	Defs.cpp
	DefsX86X64.cpp
	Logger.cpp
	MemoryManager.cpp
	MemoryMarker.cpp
	OperandX86X64.cpp
	Platform.cpp
	Util.cpp
	Assembl.cpp)
add_library(AsmJit STATIC ${LIB_AsmJit})

