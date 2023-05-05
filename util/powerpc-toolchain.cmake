# Specify the target system
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR powerpc)

# Specify the cross-compiler
set(CMAKE_C_COMPILER /home/ANT.AMAZON.COM/andhop/x-tools/powerpc-unknown-linux-gnu/bin/powerpc-unknown-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER /home/ANT.AMAZON.COM/andhop/x-tools/powerpc-unknown-linux-gnu/bin/powerpc-unknown-linux-gnu-g++)

# Specify the sysroot for the target system
set(CMAKE_SYSROOT /home/ANT.AMAZON.COM/andhop/x-tools/powerpc-unknown-linux-gnu/powerpc-unknown-linux-gnu/sysroot)
