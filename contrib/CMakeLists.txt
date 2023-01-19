# SPDX-FileCopyrightText: Copyright (c) 2023 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   add_subdirectory( boringssl-crypto )
endif ()

if( ${OBJ_CRYPTO_BUILD_TESTS} )
    set( DOCTEST_NO_INSTALL TRUE )
    add_subdirectory( doctest )
endif()
