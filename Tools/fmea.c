
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "tools.h"
#include "fmea.h"

int fme(int power, int base, int mod){
    char * buffer;
    long num = base;
    buffer = malloc (sizeof (char) * 64);
    itoa(power, buffer, 2);

    for(int i = 0; i < strlen(buffer)-1; i++){
        if(buffer[i+1] == '0'){
            num = (pow(num,2));
            num = num % mod;
        }
        else if(buffer[i+1] == '1'){
            num = ((pow(num,2)) * base);
            num = num % mod;
        }
    }

    return num;

}
