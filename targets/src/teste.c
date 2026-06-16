#include <stdio.h>
int helper(int x)
{ 
    return x * 2;
}
int main(void)
{ 
    printf("ola %d\n", helper(21)); 
    return 0; 
}