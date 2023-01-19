# SPDX-FileCopyrightText: Copyright (c) 2023 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

# find_package(OpenSSL 1.1 REQUIRED)
# find_package(doctest REQUIRED)


add_executable( testTest
    testTest.cc
)
target_link_libraries( testTest PRIVATE doctest::doctest )
add_test( NAME testTest
               COMMAND testTest )


add_executable( testVersion
    testVersion.cc
) 
target_link_libraries( testVersion PRIVATE objCrypto doctest::doctest )  
add_test( NAME testVersion
               COMMAND testVersion )


add_executable( testKeys
    testKeys.cc
) 
target_link_libraries( testKeys PRIVATE objCrypto doctest::doctest )  
add_test( NAME testKeys
               COMMAND testKeys )



add_executable ( testNulNul
    testNulNul.cc
)
target_link_libraries( testNulNul PRIVATE objCrypto doctest::doctest  )
add_test( NAME testNulNul
               COMMAND testNulNul  )


add_executable ( testAesCtr
    testAesCtr.cc
)
target_link_libraries( testAesCtr PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAesCtr
               COMMAND testAesCtr  )


add_executable ( testAesGcm
    testAesGcm.cc
)
target_link_libraries( testAesGcm PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAesGcm
               COMMAND testAesGcm  )


add_executable ( speedNul 
    speedNul.cc 
) 
target_link_libraries( speedNul PRIVATE objCrypto ) 


add_executable ( speedCtr 
    speedCtr.cc 
) 
target_link_libraries( speedCtr PRIVATE objCrypto ) 


add_executable ( speedGcm
    speedGcm.cc
)
target_link_libraries( speedGcm PRIVATE objCrypto )

