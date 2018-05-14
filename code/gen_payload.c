#include <stdio.h>
#include "utils.c"

int main(){
        // 1KiB buffer --- 1byte reserved for \0
        unsigned sizeOfBuffer = 1024,
            sizeOfPayload = (1<<26),
            written=0;
        FILE *payload;
        char buffer[sizeOfBuffer]; 

        printf("Generating %d big payload with %d buffer\n", sizeOfPayload, sizeOfBuffer);
        payload = fopen("./payload", "w");

        while (sizeOfPayload > 0){
                int i;
                for (i=0; i< sizeOfBuffer; i++)
                        buffer[i] = getVisibleChar();

                fputs(buffer, payload);
                sizeOfPayload -= sizeOfBuffer;
                written += sizeOfBuffer;
        }
        printf("Written %d bytes\n", written);

        fclose(payload);

        return 0;
}
