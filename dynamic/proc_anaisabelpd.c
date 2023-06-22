#include "../rpc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct
{
    reportable_t parent;

    char plaintext[25];   // Texto plano
    char key[25];         // Clave
    char ciphertext[25];  // Texto cifrado
} my_struct_t;

void *parse_parameters(void *data)
{
    const char *buf = (const char *)(data);

    my_struct_t *d = (my_struct_t *)(malloc(sizeof(my_struct_t)));   // Asignar memoria para la estructura


    if (d)
    {
        sscanf(buf, "%s %s", d->plaintext, d->key);  // Leer los parámetros
    }

    return (void *)d;
}

// Aqui se implementara el cifrado de Vigenère
void *do_work(void *data)
{
    my_struct_t *d = (my_struct_t *)(data);

    int plaintext_length = strlen(d->plaintext);
    int key_length = strlen(d->key);

    for (int i = 0; i < plaintext_length; i++) {
        char current_char = d->plaintext[i];
        char key_char = d->key[i % key_length];
        char encrypted_char;

        if (isalpha(current_char)) {
            // Determinar el valor base según si el carácter original es minúscula o mayúscula
            int base = islower(current_char) ? 'a' : 'A';

            // Calcular el carácter cifrado utilizando la fórmula de Vigenère
            encrypted_char = ((current_char - base) + (toupper(key_char) - 'A')) % 26 + base;
        } else {
            // Si el carácter no es una letra, mantenerlo sin cambios
            encrypted_char = current_char;
        }

        d->ciphertext[i] = encrypted_char;
    }

    // Agregar el carácter nulo al final del arreglo para indicar el final del texto cifrado
    d->ciphertext[plaintext_length] = '\0';
    return data;
}

reportable_t *report(void *data)
{
    my_struct_t *d = (my_struct_t *)(data);

    d->parent.data = (char *)(malloc(255 * sizeof(char)));

    snprintf(d->parent.data, 255, "Cifrado de Vigenere( cadena: %s, clave: %s): cadena: %s\n", d->plaintext, d->key, d->ciphertext);
    d->parent.len = strlen(d->parent.data); // Calcular la longitud del campo 'data'

    return (reportable_t *)(data);
}

void clean_up(void *params, void *result, reportable_t *report)
{
    if (report && report->data)
    {
        free(report->data);  // Liberar memoria del campo 'data' de reportable_t
    }

    if (params)
    {
        free(params);  // Liberar memoria de los parámetros
    }
}
