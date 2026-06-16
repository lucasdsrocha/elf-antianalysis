#include <stdio.h>

// Função normal que o programa vai chamar
int dobro(int x) {
    return x * 2;
}

// Constructor: roda automaticamente quando a .so é carregada.
// Serve de referência pra sabermos como código de inicialização
// deveria se comportar numa biblioteca.
__attribute__((constructor))
void ao_carregar(void) {
    printf("[constructor da libteste rodou]\n");
}
