
if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   add_subdirectory( boringssl )
endif ()

if( BUILD_TESTS )
    add_subdirectory(doctest)
endif()
