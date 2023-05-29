if (NOT DEFINED LLVM_VERSION_MAJOR)
  message(FATAL_ERROR "This project needs to be built as an LLVM project")
endif()

if (LLVM_VERSION_MAJOR LESS 8)
  message(FATAL_ERROR "This project isn't buldable with LLVM < 8.0.0.")
elseif (LLVM_VERSION_MAJOR LESS 10)
  message(WARNING "Building with LLVM < 10.0.0 is at your own risk.")
endif()

add_subdirectory(tools)
