#pragma once

#include <iostream>

inline void printHex(const char *name, void *data, int size) {
    uint8_t *ptr = (uint8_t *)data;

    std::cout << " " << name << ": ";
    for (int i = 0; i < size; i++) {
      if (( (i%4) == 0 ) && ( i>0) ) std::cout << "_" ;
      std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(ptr[i]);
    }
    std::cout << std::endl;
}
