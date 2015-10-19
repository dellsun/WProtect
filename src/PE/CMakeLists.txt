set(LIB_PE
	PEExport.cpp
	PEFile.cpp
	PEImport.cpp
	PESection.cpp
	PEReloc.cpp)
add_library(PE STATIC ${LIB_PE})
target_link_libraries(PE prlog)
