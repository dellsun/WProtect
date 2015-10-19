set(LIB_Libudis86
	decode.cpp
	itab.cpp
	syn.cpp
	syn-att.cpp
	syn-intel.cpp
	udis86.cpp)
add_library(Libudis86 STATIC ${LIB_Libudis86})
