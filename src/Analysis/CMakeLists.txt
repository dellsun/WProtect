set(LIB_Analysis
	Analysis.cpp)
add_library(Analysis STATIC ${LIB_Analysis})
target_link_libraries(Analysis Libudis86)
