#include <stdlib.h>
#include <time.h>

// returns ASCII character in range [32, 127)
char getVisibleChar(){
        unsigned long n = (random() % (127-32)) + 32;
        return (char)(n);
}

int genSeed(){
        time_t t;
        srand((unsigned) time(&t));
}
