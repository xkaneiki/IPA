# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.16.5/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.16.5/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/xkaneiki/Desktop/IPA

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/xkaneiki/Desktop/IPA/build

# Include any dependencies generated for this target.
include CMakeFiles/IPA.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/IPA.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/IPA.dir/flags.make

CMakeFiles/IPA.dir/src/main.c.o: CMakeFiles/IPA.dir/flags.make
CMakeFiles/IPA.dir/src/main.c.o: ../src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/xkaneiki/Desktop/IPA/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/IPA.dir/src/main.c.o"
	/usr/bin/clang $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/IPA.dir/src/main.c.o   -c /Users/xkaneiki/Desktop/IPA/src/main.c

CMakeFiles/IPA.dir/src/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/IPA.dir/src/main.c.i"
	/usr/bin/clang $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/xkaneiki/Desktop/IPA/src/main.c > CMakeFiles/IPA.dir/src/main.c.i

CMakeFiles/IPA.dir/src/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/IPA.dir/src/main.c.s"
	/usr/bin/clang $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/xkaneiki/Desktop/IPA/src/main.c -o CMakeFiles/IPA.dir/src/main.c.s

# Object files for target IPA
IPA_OBJECTS = \
"CMakeFiles/IPA.dir/src/main.c.o"

# External object files for target IPA
IPA_EXTERNAL_OBJECTS =

IPA: CMakeFiles/IPA.dir/src/main.c.o
IPA: CMakeFiles/IPA.dir/build.make
IPA: libsniffex.a
IPA: libhash.a
IPA: libcorrelation.a
IPA: libmyrbtree.a
IPA: CMakeFiles/IPA.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/xkaneiki/Desktop/IPA/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable IPA"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/IPA.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/IPA.dir/build: IPA

.PHONY : CMakeFiles/IPA.dir/build

CMakeFiles/IPA.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/IPA.dir/cmake_clean.cmake
.PHONY : CMakeFiles/IPA.dir/clean

CMakeFiles/IPA.dir/depend:
	cd /Users/xkaneiki/Desktop/IPA/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/xkaneiki/Desktop/IPA /Users/xkaneiki/Desktop/IPA /Users/xkaneiki/Desktop/IPA/build /Users/xkaneiki/Desktop/IPA/build /Users/xkaneiki/Desktop/IPA/build/CMakeFiles/IPA.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/IPA.dir/depend

