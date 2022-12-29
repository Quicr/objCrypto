
if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   add_subdirectory( boringssl )
endif ()

#if( ${BUILD_TESTS} )
#    set( DOCTEST_NO_INSTALL TRUE )
#    add_subdirectory(doctest)
#endif()
