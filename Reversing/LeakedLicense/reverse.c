// Reverse the algorithm in the given binary to reconstruct the data array

#include <stdio.h>

int main() {
    unsigned int data[32 * 5] = {0};  // 5 blocks of 32 bytes
    unsigned int target_chunks[5] = {
        0x726cfc2d,
        0x26c6defe,
        0xdb065621,
        0x99f5c7d0,
        0xda4f4930
    };

    for (int i = 0; i < 5; ++i) {
        unsigned int desired_v12 = target_chunks[i];
        
        for (int v6 = 31; v6 >= 0; --v6) {
            // Extract the least significant bit of `desired_v12`
            unsigned int extracted_bit = desired_v12 & 1;

            // Calculate the required value in `data[32 * i + v6]`
            data[32 * i + v6] = (extracted_bit << 31) >> v6;

            // Shift `desired_v12` right to prepare for the next bit extraction
            desired_v12 >>= 1;
        }
    }

    // Output the reconstructed data array
    printf("Reconstructed data array:\n");
    for (int i = 0; i < 32 * 5; ++i) {
        printf("0x%x, ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");  // Formatting for readability
    }
    
    return 0;
}
