set(LIB_VirtualMachine
	VMHandle.cpp
	VirtualMachine.cpp
	VirtualMachineManage.cpp
	PCode.cpp
	SeniorVMHandle.cpp
	OutDetailedInformation.cpp
	CombosVMCode.cpp
	BuildVMByteCode.cpp)
add_library(VirtualMachine STATIC ${LIB_VirtualMachine})
target_link_libraries(VirtualMachine
	AsmJit
	Algorithms
	Analysis
	CryptoPP)
