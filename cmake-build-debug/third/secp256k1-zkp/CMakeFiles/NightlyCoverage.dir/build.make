# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/michaljason/Documents/atomic_swap

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/michaljason/Documents/atomic_swap/cmake-build-debug

# Utility rule file for NightlyCoverage.

# Include any custom commands dependencies for this target.
include third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/compiler_depend.make

# Include the progress variables for this target.
include third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/progress.make

third/secp256k1-zkp/CMakeFiles/NightlyCoverage:
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp && /Applications/CLion.app/Contents/bin/cmake/mac/bin/ctest -D NightlyCoverage

NightlyCoverage: third/secp256k1-zkp/CMakeFiles/NightlyCoverage
NightlyCoverage: third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/build.make
.PHONY : NightlyCoverage

# Rule to build all files generated by this target.
third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/build: NightlyCoverage
.PHONY : third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/build

third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/clean:
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp && $(CMAKE_COMMAND) -P CMakeFiles/NightlyCoverage.dir/cmake_clean.cmake
.PHONY : third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/clean

third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/depend:
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/michaljason/Documents/atomic_swap /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp /Users/michaljason/Documents/atomic_swap/cmake-build-debug /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : third/secp256k1-zkp/CMakeFiles/NightlyCoverage.dir/depend
