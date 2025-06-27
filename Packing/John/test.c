#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

int func(int chr) {
    double A; 
    double B; 
    double C; 
    A = pow((double)chr, 5.0) * 0.5166666688;
    B = A - pow((double)chr, 4.0) * 8.125000037;
    C = pow((double)chr, 3.0) * 45.83333358 + B;
    return (int)(float)(C - pow((double)chr, 2.0) * 109.8750007 + (long double)chr * 99.65000093 + 83.99999968);
}

int main() {
    char str[] = "abcdef";
    for (int i = 33; i < 127; i++) {
        printf("%c: %d\n", i, func(i));
    }
    
}   

