add_executable(jwp jwp.cpp)
target_link_libraries(jwp
	VirtualMachine
	PE
	ELF
	prlog)
