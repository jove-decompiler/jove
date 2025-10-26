cmake_minimum_required(VERSION 3.20.0)
project(llknife)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if (LLVM_VERSION_MAJOR LESS 16)
  message(FATAL_ERROR "This project isn't buildable with LLVM < 16.0.0.")
endif()

#
# compile flags
#
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

add_executable(llknife llknife.cpp)

target_compile_options(llknife PRIVATE
  $<$<AND:$<CONFIG:RelWithDebInfo>,$<COMPILE_LANGUAGE:CXX>>:-UNDEBUG>)

target_include_directories(llknife PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(llknife PRIVATE ${LLVM_DEFINITIONS})

set_target_properties(llknife PROPERTIES
  OUTPUT_NAME "llknife-${LLVM_VERSION_MAJOR}"
)

if(DEFINED LLVM_ENABLE_RTTI AND NOT LLVM_ENABLE_RTTI)
  target_compile_options(llknife PRIVATE -fno-rtti)
endif()
if(DEFINED LLVM_ENABLE_EH AND NOT LLVM_ENABLE_EH)
  target_compile_options(llknife PRIVATE -fno-exceptions)
endif()

if(LLVM_LINK_LLVM_DYLIB)
  target_link_libraries(llknife PRIVATE LLVM)
else()
  llvm_map_components_to_libnames(LLVM_LIBS
    support
    core
    irreader
    bitreader
    bitwriter
    asmparser
    asmprinter
    analysis
    transformutils
    passes
    linker
    ipo
  )
  target_link_libraries(llknife PRIVATE ${LLVM_LIBS})
endif()

install(TARGETS llknife RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
