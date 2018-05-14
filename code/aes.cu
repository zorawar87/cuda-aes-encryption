/*
 * AES Encryption Utility implemented in CUDA
 * Author: Zorawar Moolenaar <zsingh@trincoll.edu>
 *
 * usage:
 *   1. generate random key using `make key`
 *   2. generate random payload using `make payload`
 *   3. compile using `make cuda_compile`
 *   4. GPU encrypt payload using `make cuda_enc`
 *   5. CPU encrypt payload using `make cuda_ssl`
*
 * ## Algorithm Pseudocode ##
 * The steps of AES encryption (highlited in the acommpanying paper) are based
   on pseudocode and explanation from a variety of sources including:
        """
        Announcing the Advanced Encryption Standard (AES)
        by the National Institute of Standards and Technology (2001)
        """
        and
        """
        Viability study of the CUDA technology for the acceleration of processes
        by Sánchez Castellano, Rubén (2012)
        """
 * Other resources have been cited in the accompanying paper.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda.h>

#include "aes.h"
__constant__ byte d_SBOX[256];

#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert (cudaError_t code, const char *file, int line,
                       bool abort = true) {
        if (code != cudaSuccess) {
                fprintf (stderr, "GPUassert: %s %s %d\n", cudaGetErrorString (code), file,
                         line);
                if (abort) exit (code);
        }
}


// Expanded key array definition. Its length depends on the round numbers
byte ExpandKey[60][4];

__global__
void AESEncrypt (byte* gpuBuffer, byte* key, int nStates) {
        __shared__ byte State[4][4];

        int index = blockIdx.x * blockDim.x + threadIdx.x,
            i, round;

        if (index < nStates) {
                // Every thread processes a stream of 16 bytes
                //        i.e. encrypts a block of 128bits of data
                // This 128-bit data is brought into the shared memory to provide extra speedup
                for (i = 0; i < 16; i++)
                        State[i / 4][i % 4] = gpuBuffer[i * 16 + i];

                // Add the per round Key
                AddRoundKey (State, 0, key);

                //For N-1 rounds, perform all four steps of the algorithm
                for (round = 1; round < ROUNDS; round++) {
                        SubBytes (State);
                        ShiftRows (State);
                        MixColumns (State);
                        AddRoundKey (State, round, key);
                }
                // For last round of AES Encryption, skip MixColumns
                SubBytes (State);
                ShiftRows (State);
                AddRoundKey (State, round, key);

                // Copy encrypted data back to global memory
                for (i = 0; i < 16; i++)
                        gpuBuffer[index * 16 + i] = State[i / 4][i % 4];
        }
}

int main (int argc, char** argv) {
        if (argc != 4) {
                printUsage();
                return EXIT_FAILURE;
        }

        // data path is stored in this buffer
        byte *buffer;
        buffer = (byte*)malloc (MAX_BUFFER_LENGTH);
        int bytesRead, bytesWritten, returnCode;
        // Number of state matrix stored on the buffer
        unsigned long statesInBuffer = 0,
                      processedBytes = 0;
        char pretty[20];

        FILE *payload, *target, *keyFile;
        byte Key[16];
        byte *d_payload, *d_key;

        size_t maxSz = sizeof(byte) * MAX_BUFFER_LENGTH,
               expSz = sizeof(byte) * KEY_EXPONENT;

        /////////////
        // OPEN FILES
        // READ KEY
        // EXPAND KEY
        /////////////
        prepareFiles (&payload, &target, &keyFile, argv[1], argv[2], argv[3]);
        returnCode = readKey (keyFile, Key);
        if (returnCode == EXIT_FAILURE)
                terminate (payload, target, argv[2], "Key is not 16 bytes. Terminating.");
        keyExpansion (Key);

        //////////////////// -- CUDA PLUMBING
        // allocate memory for key 
        // allocate memory for payload
        // allocate constant memory for SBOX
        // create event timers
        /////////////////////////////////////
        gpuErrchk (cudaMalloc ((void**) &d_payload, maxSz));
        gpuErrchk (cudaMalloc ((void**) &d_key, expSz));

        gpuErrchk ( cudaMemcpy (d_key, ExpandKey, expSz, cudaMemcpyHostToDevice));
        cudaMemcpyToSymbol (d_SBOX, SBOX, 256) ;

        cudaEvent_t start, stop;
        cudaEventCreate (&start);
        cudaEventCreate (&stop);
        float totalElapsedTime = 0.0;
        float elapsedtime;

        ///////////////////////////
        // Load payload into buffer
        // Run Kernel to Encrypt
        // Flush buffer to file
        ///////////////////////////
        printf ("Encrypting in Segments\n");
        bytesRead = populateBuffer (payload, buffer);
        while (bytesRead > 0) {

                statesInBuffer = bytesRead / STATE_SIZE;

                gpuErrchk (cudaMemcpy (d_payload, buffer, maxSz, cudaMemcpyHostToDevice));

                cudaEventRecord (start, 0);
                elapsedtime = 0.0;

                dim3 nBlocks(1<<15);
                dim3 nThreads(1<<10);

                AESEncrypt <<<nBlocks, nThreads>>> (d_payload, d_key, statesInBuffer);
                gpuErrchk(cudaPeekAtLastError() );

                cudaEventRecord (stop, 0);
                cudaEventSynchronize (stop);
                cudaEventElapsedTime (&elapsedtime, start, stop);
                totalElapsedTime += elapsedtime;

                gpuErrchk(cudaMemcpy (buffer, d_payload, maxSz, cudaMemcpyDeviceToHost));
                prettyPrint(bytesRead, pretty);
                printf ("...%s processed in this segment\n", pretty);

                bytesWritten = flushBuffer (buffer, statesInBuffer, target);
                if (bytesWritten < statesInBuffer) {
                        terminate (payload, target, argv[2],
                                   "Error writing the buffer on the output file" );
                }

                processedBytes += bytesRead;
                bytesRead = populateBuffer (payload, buffer);
        }

        //////////////
        // Clean-up
        // Print Stats
        //////////////
        cudaEventDestroy (start);
        cudaEventDestroy (stop);

        prettyPrint(processedBytes, pretty);
        printf ("Encrypted %s of data using %2.4fs of GPU compute time.\n",
                        pretty, totalElapsedTime/1000);

        cudaFree (d_payload); cudaFree (d_key);
        fclose (payload); fclose (target);
        return EXIT_SUCCESS;
}



/***
  * AES Utilities 
  ***/
void keyExpansion (byte *key) {
        byte temp[4];
        int word_it;

        // copy the entire key to a more accessible place
        memcpy (ExpandKey, key, KEY_SIZE_BYTES);

        //////////////////////////////////////////
        // ROTATE EACH WORD
        // SUSBTITUTE EACH WORD
        // XOR W[i-1] with round constant, Rcon[i]
        //////////////////////////////////////////
        for (int Round_it = KEY_EXPONENT; Round_it < (ROUNDS + 1) * 4; Round_it++) {
                // Get the latest word
                memcpy (temp, ExpandKey[Round_it - 1], 4);

                rotateWord (temp, 1);
                for (word_it = 0; word_it < 4; ++word_it)
                        temp[word_it] = SBOX[ (((temp[word_it] & 0xf0) >> 4) * 16) +
                                              (temp[word_it] & 0x0f)];
                temp[0] ^= Rcon[Round_it / KEY_EXPONENT];
                for (word_it = 0; word_it < 4;
                        word_it++) temp[word_it] ^= ExpandKey[Round_it - KEY_EXPONENT][word_it];

                // Save the expanded key segment
                memcpy (ExpandKey[Round_it], temp, 4);
        }
}

__host__ __device__
void rotateWord (byte* word, byte rotationCount) {
        int i;
        byte original[4];
        for (i = 0; i < 4; ++i) 
                original[i] = word[i];

        /////////////////////////////////////////////
        // 1. Shift (wrap) row 1 to the left 0 times
        // 2. Shift (wrap) row 2 to the left 1 time
        // 3. Shift (wrap) row 3 to the left 2 time
        // 4. Shift (wrap) row 4 to the left 3 time
        /////////////////////////////////////////////
        for (i = 0; i < 4; i++)
                word[i] = original[ (i + rotationCount) % 4];
}

__device__ void AddRoundKey (byte State[4][4], byte round,
                             byte* key) {
        ///////
        // Add a round key to each element of the State using XOR
        ///////
        for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++)
                        State[i][j] ^= key[ (round * 16) + (i * 4) + j];
        }
}

__device__ void SubBytes (byte State[4][4]) {
        int i, j, row, col;

        ////////////////////////////////////////////////////////
        // 1. Extract the first byte of the State Element
        // 2. Extract the second byte of the State Element
        // 3. Use the first and second byte and row and col to 
        //      find the appropriate subtituting element
        ///////////////////////////////////////////////////////
        for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                        row = (State[i][j] & 0xf0) / STATE_SIZE;
                        col = State[i][j] & 0x0f;
                        State[i][j] = d_SBOX[row * STATE_SIZE + col];
                }
        }
}

__device__ void ShiftRows (byte State[4][4]) {
        int i, j;
        byte word[4];

        /////////////////////////////////////////////
        // 0. Row 1 is not shifted
        // 1. Shift (wrap) row 2 to the left 1 time
        // 2. Shift (wrap) row 3 to the left 2 time
        // 3. Shift (wrap) row 4 to the left 3 time
        /////////////////////////////////////////////
        for (j = 1; j < 4; ++j) {
                for (i = 0; i < 4; ++i) 
                        word[i] = State[i][j];
                rotateWord (word, j);
                for (i = 0; i < 4; ++i)
                        State[i][j] = word[i];
        }
}

__device__ void MixColumns (byte State[4][4]) {
        int row, col;
        byte tmp[4];

        //////////////////////////////////////////////////////////////////////
        // This is some complex galois field operation, but it 
        // essentially boils down to matrix multiplication by a constant matrix
        //////////////////////////////////////////////////////////////////////
        for (row = 0; row < 4; ++row) {
                tmp[0] =
                        GM2[State[row][0]] ^ GM3[State[row][1]]
                        ^
                        State[row][2] ^ State[row][3];
                tmp[1] =
                        State[row][0] ^ GM2[State[row][1]]
                        ^
                        GM3[State[row][2]] ^ State[row][3];
                tmp[2] =
                        State[row][0] ^ State[row][1]
                        ^
                        GM2[State[row][2]] ^ GM3[State[row][3]];
                tmp[3] =
                        GM3[State[row][0]] ^ State[row][1]
                        ^
                        State[row][2] ^ GM2[State[row][3]];
                for (col = 0; col < 4; ++col)
                        State[row][col] = tmp[col];
        }
}

/**
  * IO utilities
  */

void prepareFiles (FILE** payload, FILE** target, FILE** keyFile,
                   char* payloadName, char* targetName, char* keyFilename) {

        printf ("\nOpening files...\n");

        *keyFile = fopen (keyFilename, "rb");
        if (*keyFile == NULL) {
                fprintf (stderr, "Could not open keyfile \"%s\"\n", keyFilename);
                exit (EXIT_FAILURE);
        } else
                printf ("Keyfile \"%s\" is ready.\n", keyFilename);

        *payload = fopen (payloadName, "rb");
        if (*payload == NULL) {
                fprintf (stderr, "Could not open payload \"%s\"\n", payloadName);
                fclose (*keyFile);
                exit (EXIT_FAILURE);
        } else
                printf ("Keyfile \"%s\" is ready.\n", payloadName);

        if (strcmp (payloadName, targetName))
                *target = fopen (targetName, "wb");

        else {
                printf ("Target file cannot be the same as payload. Writing to \n: \"%s.out\"\n",
                        targetName);
                *target = fopen (strcat (targetName, ".out"), "wb");
        }
        if (target == NULL) {
                fprintf (stderr, "Error creating writable target\n");
                fclose (*payload);
                fclose (*keyFile);
                exit (EXIT_FAILURE);
        } else
                printf ("Target file \"%s\" is ready\n", targetName);
}

int readKey (FILE *keyFile, byte key[16]) {
        int bytesRead;

        bytesRead = fread (key, 1, KEY_SIZE_BYTES, keyFile);
        printf ("\nReading 16-bytes of the given key...\n");
        if (bytesRead != KEY_SIZE_BYTES) {
                printf("Your key is %d bytes not %d per the AES Spec.\n", bytesRead, KEY_SIZE_BYTES);
                return EXIT_FAILURE;
        }

        printf ("Key successfully loaded:\n");
        printKey (key);
        printf ("Closing KeyFile...\n\n");

        fclose (keyFile);
        return EXIT_SUCCESS;
}

int populateBuffer (FILE* payload, byte *buffer) {
        int bytesRead = 0;
        // return if file is empty
        if (feof (payload)) return bytesRead;

        bytesRead = fread (buffer, 1, MAX_BUFFER_LENGTH, payload);

        char pretty[20];
        prettyPrint(bytesRead, pretty);
        printf ("...Buffer contains %s\n", pretty);
        return bytesRead;
}

int flushBuffer (byte outBuffer[], int statesInBuffer, FILE * target) {
        int bytesWritten;

        bytesWritten = fwrite (outBuffer, 1, statesInBuffer * STATE_SIZE, target);

        char pretty[20];
        prettyPrint(bytesWritten, pretty);
        printf ("...Written %s to ouput stream\n\n", pretty);
        return bytesWritten;
}

void terminate (FILE* payload, FILE* target, char* targetName, const char* msg) {
        fprintf (stderr, "\n%s\n", msg);
        fclose (payload);
        fclose (target);
        remove (targetName);
        exit (EXIT_FAILURE);
}

/**
  * Print utilities
  */

void printUsage() {
        printf ("./AESencrypt <input_file> <output_file> <key_file>'\n");
}

void printStateMatrix (byte state[4][4]) {
        for (int i = 0; i < 4; ++i)
                printf ("%02x %02x %02x %02x\n", 
                        state[i][0], state[i][1], state[i][2], state[i][3]);
        printf ("\n");
}

void printKey (byte key[16]) {
        for (int i = 0; i < KEY_SIZE_BYTES; i++)
                printf ("%02x ", key[i]);
        printf ("\n");
}

void prettyPrint (unsigned long bytes, char result[20]) {
        if (bytes > (1 << 20))
                sprintf (result, "%lu MiB", bytes / (1 << 20));
        else if (bytes > (1 << 10))
                sprintf (result, "%lu KiB", bytes / (1 << 10));
        else if (bytes > 0)
                sprintf (result, "%lu B", bytes);
        else
                sprintf (result, "): Zero Bytes :(");
}

