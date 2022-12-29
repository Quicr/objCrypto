
set(CMAKE_VERBOSE_MAKEFILE ON)

set( BAREMETAL_ARM_TOOLCHAIN_PATH /usr/bin )

#set( CMAKE_SYSTEM_NAME        Generic )
SET(CMAKE_SYSTEM_PROCESSOR armv7 )
SET(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_CROSSCOMPILING TRUE)


# Without that flag CMake is not able to pass test compilation check
set(CMAKE_TRY_COMPILE_TARGET_TYPE   STATIC_LIBRARY)

set(CMAKE_AR                       arm-none-eabi-ar )
set(CMAKE_ASM_COMPILER             arm-none-eabi-gcc )
set(CMAKE_C_COMPILER              arm-none-eabi-gcc )
set(CMAKE_CXX_COMPILER            arm-none-eabi-g++ )
#set(CMAKE_LINKER                   arm-none-eabi-ld)
#set(CMAKE_OBJCOPY                 arm-none-eabi-objcopy CACHE INTERNAL "")
#set(CMAKE_RANLIB                  arm-none-eabi-ranlib CACHE INTERNAL "")
#set(CMAKE_SIZE                    arm-none-eabi-size CACHE INTERNAL "")
#set(CMAKE_STRIP                    arm-none-eabi-strip CACHE INTERNAL "")

#set(CMAKE_C_FLAGS                   "-Wno-psabi --specs=nosys.specs -fdata-sections -ffunction-sections -Wl,--gc-sections" CACHE INTERNAL "")
set(CMAKE_C_FLAGS                   "-mlittle-endian -mcpu=cortex-m4 -march=armv7e-m -mthumb" CACHE INTERNAL "")
set(CMAKE_CXX_FLAGS                 "${CMAKE_C_FLAGS} -fno-exceptions" CACHE INTERNAL "")

set(CMAKE_C_FLAGS_DEBUG             "-Os -g" CACHE INTERNAL "")
set(CMAKE_C_FLAGS_RELEASE           "-Os -DNDEBUG" CACHE INTERNAL "")
set(CMAKE_CXX_FLAGS_DEBUG           "${CMAKE_C_FLAGS_DEBUG}" CACHE INTERNAL "")
set(CMAKE_CXX_FLAGS_RELEASE         "${CMAKE_C_FLAGS_RELEASE}" CACHE INTERNAL "")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set( BUILD_TESTS False )

