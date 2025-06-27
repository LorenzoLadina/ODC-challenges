// Use the same code of the challenge but with the correct data array to produce the flag.
#include <stdio.h>

int i; // [rsp+14h] [rbp-7Ch]
int j; // [rsp+14h] [rbp-7Ch]
int v6; // [rsp+18h] [rbp-78h]
int v7; // [rsp+18h] [rbp-78h]
int k; // [rsp+20h] [rbp-70h]
int m; // [rsp+24h] [rbp-6Ch]
long int v10; // [rsp+28h] [rbp-68h]
long int v11; // [rsp+30h] [rbp-60h]
unsigned long int v12; // [rsp+38h] [rbp-58h]
unsigned long int v13; // [rsp+38h] [rbp-58h]
long int v14; // [rsp+48h] [rbp-48h]
long int v15; // [rsp+50h] [rbp-40h]
long int v16; // [rsp+58h] [rbp-38h]
unsigned long int v17; // [rsp+60h] [rbp-30h]
long int v18; // [rsp+68h] [rbp-28h]
long int v19; // [rsp+70h] [rbp-20h]
unsigned long int v20; // [rsp+78h] [rbp-18h]
long int v21; // [rsp+80h] [rbp-10h]


unsigned int data[] = {
    0x0, 0x40000000, 0x20000000, 0x10000000, 0x0, 0x0, 0x2000000, 0x0, 0x0, 0x400000, 0x200000, 0x0, 0x80000, 0x40000, 0x0, 0x0, 
    0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x8, 0x4, 0x0, 0x1, 
    0x0, 0x0, 0x20000000, 0x0, 0x0, 0x4000000, 0x2000000, 0x0, 0x800000, 0x400000, 0x0, 0x0, 0x0, 0x40000, 0x20000, 0x0, 
    0x8000, 0x4000, 0x0, 0x1000, 0x800, 0x400, 0x200, 0x0, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x0, 
    0x80000000, 0x40000000, 0x0, 0x10000000, 0x8000000, 0x0, 0x2000000, 0x1000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40000, 0x20000, 0x0, 
    0x0, 0x4000, 0x0, 0x1000, 0x0, 0x400, 0x200, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x1, 
    0x80000000, 0x0, 0x0, 0x10000000, 0x8000000, 0x0, 0x0, 0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x0, 0x40000, 0x0, 0x10000, 
    0x8000, 0x4000, 0x0, 0x0, 0x0, 0x400, 0x200, 0x100, 0x80, 0x40, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 
    0x80000000, 0x40000000, 0x0, 0x10000000, 0x8000000, 0x0, 0x2000000, 0x0, 0x0, 0x400000, 0x0, 0x0, 0x80000, 0x40000, 0x20000, 0x10000, 
    0x0, 0x4000, 0x0, 0x0, 0x800, 0x0, 0x0, 0x100, 0x0, 0x0, 0x20, 0x10, 0x0, 0x0, 0x0, 0x0
};  // 5 blocks of 32 bytes

unsigned int data_2[] = {
    0x34651A74,
    0x7cb8d7e7,
    0xaac78f4d,
    0x261611d5,
    0xf87ae218,
    0x218d22dd,
    0x9a4a4d0f,
    0xd78cebe8
};

int main() {

  v10 = 0LL;
  
  printf("License number: ");
  for ( i = 0; i <= 4; ++i )
  {
    v6 = 0;
    v12 = 0LL;
    while ( v6 <= 31 )
    {
      v12 = ((unsigned int)(data[32 * i + v6] << v6) >> 31) | (2 * v12);
      ++v6;
    }
    printf("%04lx", v12);
  }  
  printf("\nSerial code: ");
  for ( j = 0; j <= 4; ++j )
  {
    v7 = 0;
    v13 = 0LL;
    while ( v7 <= 31 )
    {
      v13 = ((unsigned int)(data[32 * j + v7] << v7) >> 31) | (2 * v13);
      ++v7;
    }
    v14 = data_2[0];
    for ( k = 1; k <= 7; ++k )
    {
      v15 = 1LL;
      for ( m = 0; m < k; ++m )
      {
        v16 = v15;
        v17 = v13;
        v18 = 0LL;
        while ( v17 && v16 )
        {
          if ( (v17 & 1) != 0 )
            v18 ^= v16;
          v16 *= 2LL;
          if ( (v16 & 0x100000000LL) != 0 )
            v16 ^= 0x10000008DuLL;
          v17 >>= 1;
        }
        v15 = v18;
      }
      v19 = data_2[k];
      v20 = v15;
      v21 = 0LL;
      while ( v20 && v19 )
      {
        if ( (v20 & 1) != 0 )
          v21 ^= v19;
        v19 *= 2LL;
        if ( (v19 & 0x100000000LL) != 0 )
          v19 ^= 0x10000008DuLL;
        v20 >>= 1;
      }
      v14 ^= v21;
    }
    v11 = v10 ^ v14;
    v10 ^= v14;
    if ( j != 4 )
      printf("%04lx-", v11);
  }
  printf("%04lx\n", v11);
  return 0LL;

}
