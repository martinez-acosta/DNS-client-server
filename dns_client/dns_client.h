#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H
#include <arpa/inet.h>  //htons
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <resolv.h>
#include <stdbool.h>
#include <stdio.h>  //perror
#include <stdlib.h>
#include <string.h>  //memset
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "cmdline.h"

#define DEFAULT_SERVER_PORT 53

#define QTYPE_A 1
#define QTYPE_AAAA 28
#define QTYPE_NS 2
#define QTYPE_CNAME 5
#define QTYPE_SOA 6

#define QCLASS_IN 1

#define MAX_BUFSIZE 1500

typedef struct dns_addr {

    char     domain[255];     // Nombre del dominio
    uint16_t type;            // Tipo de registro
    uint16_t class_internet;  // Clase
    uint32_t ttl;             // Tiempo de vida
    uint16_t data_length;     // Longitud del segmento de datos

    /* Posibles combinaciones: */
    struct in_addr  addr;              // Dirección IPv4 ( A )
    struct in6_addr sin6_addr;         // Dirección IPv6 ( AAAA )
    char            name_server[255];  // Dominio al que pertenece ( NS )
    char            alias[255];        // Alias ( CNAME )

    struct dns_addr *next;  // Siguiente elemento

} dns_addr;

typedef struct dns_msg {

    uint16_t answerRRCount;
    uint16_t authRRCount;
    uint16_t additionalRRCount;
    uint16_t questionCount;  // número de preguntas

    uint16_t tid;
    uint16_t rcode;
    uint16_t opcode;
    uint16_t elements_list;
    uint16_t qtype;

} dns_msg;

typedef struct dns_client {

    int       descriptor;   // Descriptor de socket
    int       size_buf;     // Tamaño de bytes a enviar
    ssize_t   received;     // Tamaño de datos recibidos
    u_int16_t server_port;  // Puerto del servidor

    char domain[255];  // Nombre de dominio del que queremos obtener la IP

    u_char buf[MAX_BUFSIZE];         // buffer para enviar y recibir peticiones DNS
    u_char buf_backup[MAX_BUFSIZE];  // buffer de respaldo de la última respuesta/petición

    struct dns_msg     msg;      // Datos correspondientes a la petición DNS
    struct sockaddr_in addr;     // Dirección IP del proceso
    struct sockaddr_in remote;   // Dirección IP remota
    struct timeval     timeout;  // tiempo de espera para cada msg

    socklen_t size_addr;    // Tamaño de la structura sockaddr_in
    socklen_t size_remote;  // Tamaño de la structura sockaddr_in remota

    bool start;       // Estado de inicio
    bool end;         // Estado de terminación
    bool is_timeout;  // Si se ha excedido el tiempo de espera

    int       ns_response;
    int       retries;  // Número de reintentos
    u_int16_t flags;

    dns_addr *head;
    dns_addr *tail;

} dns_client;

void get_name ( u_char *buf, u_char *p, char *name );
int encode_name ( u_char *p, char *domain );
void dns_receive_response ( dns_client *client );
void free_dns_list ( dns_addr *head );
void dns_send_request ( dns_client *client );
void dns_build_request ( dns_client *client );
void dns_get_response ( dns_client *client );
void dns_init ( dns_client *client, struct gengetopt_args_info *args_info );
void dns_next_request ( dns_client *client );
void dns_print_response ( dns_client *client );

/* Función: get_name() */
// Sirve para obtener la cadena correspondiente a una trama en la que está comprimido  con notación DNS
// Parámetros:
// u_char * buf: Posición inicial de la trama DNS
// u_char  * p: Posición actual de la trama DNS
// char  * name: Cadena en donde se almacenará el nombre

/* Función: get_list_response() */
// Sirve para obtener una lista simple enlazada correspondiente a todos los registros tipo A, NS, AAAA y CNAME de una
// respuesta DNS
// Parámetros:
// dns_client * client: Apuntador a la estructura principal

/* Función: encode_name() */
// Comprime un nombre de dominio en notación DNS
// Parámetros:
// u_char *p: Posición actual
// char *domain: Nombre de dominio a comprimir

/* Función: dns_receive_response() */
// Se encarga de recibir respuestas DNS y retransmitirlas si es necesario
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: free_dns_list() */
// Libera la memoria reservada dinámicamente de una lista simple enlazada tipo dns_addr
// Parámetros:
// dns_addr * head: Apuntador al primer elemento de la lista

/* Función: dns_send_request() */
// Envía petición DNS
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: dns_build_request() */
// Construye la trama a enviar
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: dns_get_response() */
// Obtiene una respuesta DNS
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: dns_init() */
// Inicializaciones generales
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: dns_next_request() */
// Decide cuál será la siguiente IP a la que se hará una petición DNS
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

/* Función: dns_print_response() */
// Imprime en pantalla respuesta DNS
// Parámetros:
// dns_client * client: Apuntador a la estructura de control principal

#endif  // DNS_CLIENT_H
