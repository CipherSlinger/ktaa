# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jianye/Desktop/coding

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jianye/Desktop/coding/build

# Include any dependencies generated for this target.
include CMakeFiles/emura.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/emura.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/emura.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/emura.dir/flags.make

CMakeFiles/emura.dir/emura.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/emura.cpp.o: /home/jianye/Desktop/coding/emura.cpp
CMakeFiles/emura.dir/emura.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/emura.dir/emura.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/emura.cpp.o -MF CMakeFiles/emura.dir/emura.cpp.o.d -o CMakeFiles/emura.dir/emura.cpp.o -c /home/jianye/Desktop/coding/emura.cpp

CMakeFiles/emura.dir/emura.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/emura.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/emura.cpp > CMakeFiles/emura.dir/emura.cpp.i

CMakeFiles/emura.dir/emura.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/emura.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/emura.cpp -o CMakeFiles/emura.dir/emura.cpp.s

CMakeFiles/emura.dir/src/Group.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/src/Group.cpp.o: /home/jianye/Desktop/coding/src/Group.cpp
CMakeFiles/emura.dir/src/Group.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/emura.dir/src/Group.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/src/Group.cpp.o -MF CMakeFiles/emura.dir/src/Group.cpp.o.d -o CMakeFiles/emura.dir/src/Group.cpp.o -c /home/jianye/Desktop/coding/src/Group.cpp

CMakeFiles/emura.dir/src/Group.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/src/Group.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/src/Group.cpp > CMakeFiles/emura.dir/src/Group.cpp.i

CMakeFiles/emura.dir/src/Group.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/src/Group.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/src/Group.cpp -o CMakeFiles/emura.dir/src/Group.cpp.s

CMakeFiles/emura.dir/src/Pairing.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/src/Pairing.cpp.o: /home/jianye/Desktop/coding/src/Pairing.cpp
CMakeFiles/emura.dir/src/Pairing.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/emura.dir/src/Pairing.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/src/Pairing.cpp.o -MF CMakeFiles/emura.dir/src/Pairing.cpp.o.d -o CMakeFiles/emura.dir/src/Pairing.cpp.o -c /home/jianye/Desktop/coding/src/Pairing.cpp

CMakeFiles/emura.dir/src/Pairing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/src/Pairing.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/src/Pairing.cpp > CMakeFiles/emura.dir/src/Pairing.cpp.i

CMakeFiles/emura.dir/src/Pairing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/src/Pairing.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/src/Pairing.cpp -o CMakeFiles/emura.dir/src/Pairing.cpp.s

CMakeFiles/emura.dir/src/SHA256.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/src/SHA256.cpp.o: /home/jianye/Desktop/coding/src/SHA256.cpp
CMakeFiles/emura.dir/src/SHA256.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/emura.dir/src/SHA256.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/src/SHA256.cpp.o -MF CMakeFiles/emura.dir/src/SHA256.cpp.o.d -o CMakeFiles/emura.dir/src/SHA256.cpp.o -c /home/jianye/Desktop/coding/src/SHA256.cpp

CMakeFiles/emura.dir/src/SHA256.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/src/SHA256.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/src/SHA256.cpp > CMakeFiles/emura.dir/src/SHA256.cpp.i

CMakeFiles/emura.dir/src/SHA256.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/src/SHA256.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/src/SHA256.cpp -o CMakeFiles/emura.dir/src/SHA256.cpp.s

CMakeFiles/emura.dir/src/Zr.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/src/Zr.cpp.o: /home/jianye/Desktop/coding/src/Zr.cpp
CMakeFiles/emura.dir/src/Zr.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/emura.dir/src/Zr.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/src/Zr.cpp.o -MF CMakeFiles/emura.dir/src/Zr.cpp.o.d -o CMakeFiles/emura.dir/src/Zr.cpp.o -c /home/jianye/Desktop/coding/src/Zr.cpp

CMakeFiles/emura.dir/src/Zr.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/src/Zr.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/src/Zr.cpp > CMakeFiles/emura.dir/src/Zr.cpp.i

CMakeFiles/emura.dir/src/Zr.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/src/Zr.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/src/Zr.cpp -o CMakeFiles/emura.dir/src/Zr.cpp.s

CMakeFiles/emura.dir/src/Timer.cpp.o: CMakeFiles/emura.dir/flags.make
CMakeFiles/emura.dir/src/Timer.cpp.o: /home/jianye/Desktop/coding/src/Timer.cpp
CMakeFiles/emura.dir/src/Timer.cpp.o: CMakeFiles/emura.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/emura.dir/src/Timer.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/emura.dir/src/Timer.cpp.o -MF CMakeFiles/emura.dir/src/Timer.cpp.o.d -o CMakeFiles/emura.dir/src/Timer.cpp.o -c /home/jianye/Desktop/coding/src/Timer.cpp

CMakeFiles/emura.dir/src/Timer.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/emura.dir/src/Timer.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jianye/Desktop/coding/src/Timer.cpp > CMakeFiles/emura.dir/src/Timer.cpp.i

CMakeFiles/emura.dir/src/Timer.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/emura.dir/src/Timer.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jianye/Desktop/coding/src/Timer.cpp -o CMakeFiles/emura.dir/src/Timer.cpp.s

# Object files for target emura
emura_OBJECTS = \
"CMakeFiles/emura.dir/emura.cpp.o" \
"CMakeFiles/emura.dir/src/Group.cpp.o" \
"CMakeFiles/emura.dir/src/Pairing.cpp.o" \
"CMakeFiles/emura.dir/src/SHA256.cpp.o" \
"CMakeFiles/emura.dir/src/Zr.cpp.o" \
"CMakeFiles/emura.dir/src/Timer.cpp.o"

# External object files for target emura
emura_EXTERNAL_OBJECTS =

/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/emura.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/src/Group.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/src/Pairing.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/src/SHA256.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/src/Zr.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/src/Timer.cpp.o
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/build.make
/home/jianye/Desktop/coding/bin/emura: CMakeFiles/emura.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/jianye/Desktop/coding/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX executable /home/jianye/Desktop/coding/bin/emura"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/emura.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/emura.dir/build: /home/jianye/Desktop/coding/bin/emura
.PHONY : CMakeFiles/emura.dir/build

CMakeFiles/emura.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/emura.dir/cmake_clean.cmake
.PHONY : CMakeFiles/emura.dir/clean

CMakeFiles/emura.dir/depend:
	cd /home/jianye/Desktop/coding/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jianye/Desktop/coding /home/jianye/Desktop/coding /home/jianye/Desktop/coding/build /home/jianye/Desktop/coding/build /home/jianye/Desktop/coding/build/CMakeFiles/emura.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/emura.dir/depend
