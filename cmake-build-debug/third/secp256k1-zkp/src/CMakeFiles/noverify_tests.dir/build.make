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

# Include any dependencies generated for this target.
include third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/compiler_depend.make

# Include the progress variables for this target.
include third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/progress.make

# Include the compile flags for this target's objects.
include third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/flags.make

third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o: third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/flags.make
third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o: /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp/src/tests.c
third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o: third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/michaljason/Documents/atomic_swap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o"
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o -MF CMakeFiles/noverify_tests.dir/tests.c.o.d -o CMakeFiles/noverify_tests.dir/tests.c.o -c /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp/src/tests.c

third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/noverify_tests.dir/tests.c.i"
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp/src/tests.c > CMakeFiles/noverify_tests.dir/tests.c.i

third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/noverify_tests.dir/tests.c.s"
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp/src/tests.c -o CMakeFiles/noverify_tests.dir/tests.c.s

# Object files for target noverify_tests
noverify_tests_OBJECTS = \
"CMakeFiles/noverify_tests.dir/tests.c.o"

# External object files for target noverify_tests
noverify_tests_EXTERNAL_OBJECTS = \
"/Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src/CMakeFiles/secp256k1_precomputed.dir/precomputed_ecmult.c.o" \
"/Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src/CMakeFiles/secp256k1_precomputed.dir/precomputed_ecmult_gen.c.o"

third/secp256k1-zkp/src/noverify_tests: third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/tests.c.o
third/secp256k1-zkp/src/noverify_tests: third/secp256k1-zkp/src/CMakeFiles/secp256k1_precomputed.dir/precomputed_ecmult.c.o
third/secp256k1-zkp/src/noverify_tests: third/secp256k1-zkp/src/CMakeFiles/secp256k1_precomputed.dir/precomputed_ecmult_gen.c.o
third/secp256k1-zkp/src/noverify_tests: third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/build.make
third/secp256k1-zkp/src/noverify_tests: third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/michaljason/Documents/atomic_swap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable noverify_tests"
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/noverify_tests.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/build: third/secp256k1-zkp/src/noverify_tests
.PHONY : third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/build

third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/clean:
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src && $(CMAKE_COMMAND) -P CMakeFiles/noverify_tests.dir/cmake_clean.cmake
.PHONY : third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/clean

third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/depend:
	cd /Users/michaljason/Documents/atomic_swap/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/michaljason/Documents/atomic_swap /Users/michaljason/Documents/atomic_swap/third/secp256k1-zkp/src /Users/michaljason/Documents/atomic_swap/cmake-build-debug /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src /Users/michaljason/Documents/atomic_swap/cmake-build-debug/third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : third/secp256k1-zkp/src/CMakeFiles/noverify_tests.dir/depend

