//c++ implementation of pseudo-code on SHA-2 Wikipedia page
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct chunk { 
	uint8_t& operator[](int i){ return words[i]; }
	uint8_t words[64];
	} chunk;

//initialized hash values (first 32 bits of the fractional parts of 
//the square roots of the first 8 primes 2..19)
uint32_t hashValues[] = {0x6a09e667,
							 0xbb67ae85,
							 0x3c6ef372,
							 0xa54ff53a,
							 0x510e527f,
							 0x9b05688c,
							 0x1f83d9ab,
							 0x5be0cd19
							};

//initialized round constants
//(first 32 bits of the fractional parts 
//of the cube roots of the first 64 primes 2..311)
uint32_t roundConstants[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
							   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
							   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
							   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
							   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
							   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
							   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
							   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
								};

//implementation of bitwise right rotation for 32 bit unsigned integers
uint32_t RotateRight32(uint32_t num, uint32_t shiftBy){
	shiftBy = shiftBy % 32;
	
	uint32_t shifted = num >> shiftBy;
	uint32_t rotated = num << (32 - shiftBy);
	
	return rotated | shifted;
}

void SHA256(const char* message){
	//Pre-processing (Padding)
	const int MESSAGELENGTH = strlen(message);
	const int NUMCHUNKS = MESSAGELENGTH / 64 + 1 + (MESSAGELENGTH % 64) / 56; //the number of 8 bit chunks
	chunk chunks[NUMCHUNKS] = {0}; //array to hold postprocessed message
	uint64_t L = MESSAGELENGTH * 8; //length of original message in bits
	int K = 512 - (L % 512) - 65; //minimum number of bits such that L + 1 + K + 64 is a multiple of 512
	int j;
	for(int i = 0; i < NUMCHUNKS; i++){//populate chunks array
		if(i < NUMCHUNKS - 1)
			for(j = 0; j < 64; j++){
				chunks[i][j] = (uint8_t)message[64 * i + j];
			}
		else{
			for(j = 0; j < MESSAGELENGTH % 64; j++){
				chunks[i][j] = (uint8_t)message[64 * i + j];
			}
			break;
		}
	}

	chunks[NUMCHUNKS - 1][j] = 0b10000000; //append 1 and 7 0s
	for(int i = 0; i < (K - 7) / 8; i++){ //append K-7 0s
		chunks[NUMCHUNKS - 1][j + 1 + i] = 0;
	}
	for(int i = 0; i < 8; i++){ //append L
		chunks[NUMCHUNKS - 1][j + (K + 1) / 8 + i] = (L >> (8 * (7 - i))) & 0b11111111;
	}

	//Process the message in successive 512-bit chunks
	uint32_t messageScheduleArrays[NUMCHUNKS][64] = {0};
	for(int i = 0; i < NUMCHUNKS; i++){
		//copy chunks into first 16 words of each message schedule array
		for(int j = 0; j < 16; j++){
			messageScheduleArrays[i][j] |= (chunks[i][4 * j] << 24) | (chunks[i][4 * j + 1] << 16) | (chunks[i][4 * j + 2] << 8) | chunks[i][4 * j + 3];
		}

		//extend the first 16 words into the remaining 48 words of the messageScheduleArray
		for(int j = 16; j < 64; j++){
			uint32_t s0 = RotateRight32(messageScheduleArrays[i][j - 15], 7) ^ RotateRight32(messageScheduleArrays[i][j - 15], 18) ^ (messageScheduleArrays[i][j - 15] >> 3);
			uint32_t s1 = RotateRight32(messageScheduleArrays[i][j - 2], 17) ^ RotateRight32(messageScheduleArrays[i][j - 2], 19) ^ (messageScheduleArrays[i][j - 2] >> 10);
			messageScheduleArrays[i][j] = messageScheduleArrays[i][j - 16] + s0 + messageScheduleArrays[i][j - 7] + s1;
		}
		
		uint32_t workingVariables[8];
		memcpy(workingVariables, hashValues, sizeof workingVariables);
		
		//compression function main loop
		for(int j = 0; j < 64; j++){
			uint32_t S1 = RotateRight32(workingVariables[4], 6) ^ RotateRight32(workingVariables[4], 11) ^ RotateRight32(workingVariables[4], 25);
			uint32_t ch = (workingVariables[4] & workingVariables[5]) ^ ((~workingVariables[4]) & workingVariables[6]);
			uint32_t temp1 = workingVariables[7] + S1 + ch + roundConstants[j] + messageScheduleArrays[i][j];
			uint32_t S0 = RotateRight32(workingVariables[0], 2) ^ RotateRight32(workingVariables[0], 13) ^ RotateRight32(workingVariables[0], 22);
			uint32_t maj = (workingVariables[0] & workingVariables[1]) ^ (workingVariables[0] & workingVariables[2]) ^ (workingVariables[1] & workingVariables[2]);
			uint32_t temp2 = S0 + maj;
			
			workingVariables[7] = workingVariables[6];
			workingVariables[6] = workingVariables[5];
			workingVariables[5] = workingVariables[4];
			workingVariables[4] = workingVariables[3] + temp1;
			workingVariables[3] = workingVariables[2];
			workingVariables[2] = workingVariables[1];
			workingVariables[1] = workingVariables[0];
			workingVariables[0] = temp1 + temp2;
		}
		
		//Add the compressed chunk to the current hash value
		for(int j = 0; j < 8; j++){
			hashValues[j] += workingVariables[j];
		}
	}
	
	//Produce the final hash value
	for(int i = 0; i < 8; i++){
		printf("%#010x\n", hashValues[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	const char* message = "";
	SHA256(message);
	return 0;
}
