#include <stdio.h>
#include "utils.c"


int main(){
        FILE *out = fopen("./key", "w");

        // 16 bytes of data i.e. 128bit key
        int sizeOfKey = 16;

        genSeed();
        while (sizeOfKey--)
                fprintf(out,"%c", getVisibleChar());
        printf("\n");
        fclose(out);

        return 0;
}
