#include <stdio.h>
extern int helper(int);
extern int soma(int, int);
int main(void) {
    printf("helper: %d, soma: %d\n", helper(21), soma(3, 4));
    return 0;
}
