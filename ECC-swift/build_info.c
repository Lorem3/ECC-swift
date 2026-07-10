//
//  build_info.c
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

#include "build_info.h"

const char *get_build_date(void) {
    return __DATE__;
}

const char *get_build_time(void) {
    return __TIME__;
}
