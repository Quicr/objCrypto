# SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

add_executable ( objCryptoExampleA 
    objCryptoExampleA.cc 
) 
target_link_libraries( objCryptoExampleA PRIVATE objCrypto ) 

