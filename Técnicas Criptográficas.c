/*
=============================================================================
  SISTEMA DE CRIPTOGRAFIA - OPERAÇÃO NAVIO TÓXICO
  Guarda Costeira Brasileira - Controle de Acesso à Área Contaminada
=============================================================================
  Técnica: Cifra de Vigenère (polialfabética com chave secreta)
  Contexto: Navio apreendido com lixo tóxico radioativo a 50 km da costa.
            Apenas inspetores autorizados com a chave secreta podem
            cifrar/decifrar comunicações operacionais.
  Limite de mensagem: 128 caracteres
=============================================================================
  Compilar no VS Code (terminal):
      gcc navio_cripto.c -o navio_cripto
  Executar:
      ./navio_cripto          (Linux/Mac)
      navio_cripto.exe        (Windows)
=============================================================================
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX_MSG  129   /* 128 chars + '\0' */
#define MAX_KEY  65    /* chave até 64 chars */

/* -------------------------------------------------------------------------
   BANNER de apresentação
   ---------------------------------------------------------------------- */
void exibir_banner(void)
{
    printf("\n");
    printf("  ============================================================\n");
    printf("  |   OPERACAO NAVIO TOXICO - GUARDA COSTEIRA BRASILEIRA    |\n");
    printf("  |   Sistema Criptografico de Comunicacao Segura           |\n");
    printf("  |   Tecnica: Cifra de Vigenere (polialfabetica)           |\n");
    printf("  ============================================================\n");
    printf("  Distancia do navio: 50 km da costa\n");
    printf("  Raio de isolamento: 10 km\n");
    printf("  Acesso: apenas por helicoptero / inspetores autorizados\n");
    printf("  ------------------------------------------------------------\n\n");
}

/* -------------------------------------------------------------------------
   Explicação didática da Cifra de Vigenère
   ---------------------------------------------------------------------- */
void explicar_tecnica(void)
{
    printf("\n  === SOBRE A CIFRA DE VIGENERE ===\n");
    printf("  A Cifra de Vigenere e uma tecnica de criptografia poliafabetica.\n");
    printf("  Cada letra da mensagem e deslocada por um valor diferente,\n");
    printf("  determinado pela letra correspondente na CHAVE SECRETA.\n\n");
    printf("  Formula de cifragem:\n");
    printf("    C[i] = (M[i] + K[i]) mod 26\n");
    printf("  Formula de decifragem:\n");
    printf("    M[i] = (C[i] - K[i] + 26) mod 26\n\n");
    printf("  Onde M = mensagem, K = chave, C = cifrado (apenas letras A-Z).\n");
    printf("  Numeros, espacos e simbolos sao mantidos sem alteracao.\n");
    printf("  ================================================\n\n");
}

/* -------------------------------------------------------------------------
   Cifrar mensagem com Vigenère
   msg     : texto original (entrada)
   chave   : chave secreta (somente letras)
   saida   : buffer de saída (mesmo tamanho que msg)
   ---------------------------------------------------------------------- */
void cifrar(const char *msg, const char *chave, char *saida)
{
    int tam_chave = (int)strlen(chave);
    int k = 0;   /* índice dentro da chave */

    for (int i = 0; msg[i] != '\0'; i++) {
        char c = msg[i];

        if (isalpha(c)) {
            char base    = isupper(c) ? 'A' : 'a';
            int  deslocamento = toupper(chave[k % tam_chave]) - 'A';
            saida[i] = (char)(base + (c - base + deslocamento) % 26);
            k++;   /* avança a chave apenas para letras */
        } else {
            /* dígitos, espaços, pontuação: mantidos como estão */
            saida[i] = c;
        }
    }
    saida[strlen(msg)] = '\0';
}

/* -------------------------------------------------------------------------
   Decifrar mensagem com Vigenère
   ---------------------------------------------------------------------- */
void decifrar(const char *msg_cifrada, const char *chave, char *saida)
{
    int tam_chave = (int)strlen(chave);
    int k = 0;

    for (int i = 0; msg_cifrada[i] != '\0'; i++) {
        char c = msg_cifrada[i];

        if (isalpha(c)) {
            char base    = isupper(c) ? 'A' : 'a';
            int  deslocamento = toupper(chave[k % tam_chave]) - 'A';
            saida[i] = (char)(base + (c - base - deslocamento + 26) % 26);
            k++;
        } else {
            saida[i] = c;
        }
    }
    saida[strlen(msg_cifrada)] = '\0';
}

/* -------------------------------------------------------------------------
   Valida se a chave contém apenas letras
   ---------------------------------------------------------------------- */
int chave_valida(const char *chave)
{
    if (strlen(chave) == 0) return 0;
    for (int i = 0; chave[i] != '\0'; i++) {
        if (!isalpha(chave[i])) return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------
   Leitura de string com fgets (evita buffer overflow)
   ---------------------------------------------------------------------- */
void ler_linha(char *buf, int tamanho)
{
    if (fgets(buf, tamanho, stdin)) {
        /* remove '\n' final, se houver */
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
    }
}

/* -------------------------------------------------------------------------
   Demo automático com frase e chave pré-definidas
   ---------------------------------------------------------------------- */
void demonstracao(void)
{
    /* Frase e chave fornecidas pelo sistema para uso dos inspetores */
    const char *frase_demo =
        "Inspetor autorizado solicita acesso ao Navio Setor 3 em 50 km";
    const char *chave_demo = "GUARDACOSTEIRA";

    char cifrado[MAX_MSG];
    char decifrado[MAX_MSG];

    printf("\n  === DEMONSTRACAO AUTOMATICA ===\n");
    printf("  Frase original  : %s\n", frase_demo);
    printf("  Chave secreta   : %s\n", chave_demo);

    cifrar(frase_demo, chave_demo, cifrado);
    printf("  Mensagem cifrada: %s\n", cifrado);

    decifrar(cifrado, chave_demo, decifrado);
    printf("  Msg decifrada   : %s\n", decifrado);

    printf("\n  [Verificacao: original == decifrado? %s]\n",
           strcmp(frase_demo, decifrado) == 0 ? "SIM - OK" : "NAO - ERRO");
    printf("  ================================================\n\n");
}

/* =========================================================================
   MAIN
   ====================================================================== */
int main(void)
{
    exibir_banner();
    explicar_tecnica();
    demonstracao();

    char opcao_str[8];
    int  opcao;
    char mensagem[MAX_MSG];
    char chave[MAX_KEY];
    char resultado[MAX_MSG];

    while (1) {
        printf("  ============================================================\n");
        printf("  MENU PRINCIPAL\n");
        printf("  ------------------------------------------------------------\n");
        printf("  1 - Cifrar mensagem\n");
        printf("  2 - Decifrar mensagem\n");
        printf("  3 - Ver frase e chave de demonstracao novamente\n");
        printf("  0 - Sair\n");
        printf("  ------------------------------------------------------------\n");
        printf("  Escolha: ");
        ler_linha(opcao_str, sizeof(opcao_str));
        opcao = atoi(opcao_str);

        if (opcao == 0) {
            printf("\n  Sistema encerrado. Operacao encerrada com seguranca.\n\n");
            break;
        }

        switch (opcao) {

        /* ---- CIFRAR ---- */
        case 1:
            printf("\n  [CIFRAGEM]\n");
            printf("  Digite a mensagem (ate 128 caracteres):\n  > ");
            ler_linha(mensagem, MAX_MSG);

            if (strlen(mensagem) == 0) {
                printf("  ERRO: mensagem vazia.\n\n");
                break;
            }

            printf("  Digite a chave secreta (somente letras, sem espacos):\n  > ");
            ler_linha(chave, MAX_KEY);

            if (!chave_valida(chave)) {
                printf("  ERRO: chave invalida. Use apenas letras (A-Z / a-z).\n\n");
                break;
            }

            cifrar(mensagem, chave, resultado);
            printf("\n  Mensagem original : %s\n", mensagem);
            printf("  Chave utilizada   : %s\n", chave);
            printf("  Mensagem CIFRADA  : %s\n\n", resultado);
            break;

        /* ---- DECIFRAR ---- */
        case 2:
            printf("\n  [DECIFRAGEM]\n");
            printf("  Digite a mensagem cifrada (ate 128 caracteres):\n  > ");
            ler_linha(mensagem, MAX_MSG);

            if (strlen(mensagem) == 0) {
                printf("  ERRO: mensagem vazia.\n\n");
                break;
            }

            printf("  Digite a chave secreta (somente letras, sem espacos):\n  > ");
            ler_linha(chave, MAX_KEY);

            if (!chave_valida(chave)) {
                printf("  ERRO: chave invalida. Use apenas letras (A-Z / a-z).\n\n");
                break;
            }

            decifrar(mensagem, chave, resultado);
            printf("\n  Mensagem cifrada  : %s\n", mensagem);
            printf("  Chave utilizada   : %s\n", chave);
            printf("  Mensagem ORIGINAL : %s\n\n", resultado);
            break;

        /* ---- DEMO ---- */
        case 3:
            demonstracao();
            break;

        default:
            printf("  Opcao invalida. Tente novamente.\n\n");
        }
    }

    return 0;
}