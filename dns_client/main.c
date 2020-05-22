#include "dns_client.h"

int main ( int argc, char *argv[] ) {

    struct gengetopt_args_info args_info;
    srand ( time ( NULL ) );
    dns_client client;

    /* Obtenemos las opciones de comando */

    if ( cmdline_parser ( argc, argv, &args_info ) != 0 )
        exit ( EXIT_FAILURE );

    /* Inicializamos */
    dns_init ( &client, &args_info );

    while ( 1 ) {

        dns_get_response ( &client );
        dns_print_response ( &client );

        if ( client.end )
            exit ( 0 );

        dns_next_request ( &client );

        // Limpiamos lista enlazada
        free_dns_list ( client.head );
        client.head = malloc ( sizeof ( dns_addr ) );
    }
}

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

void get_list_response ( dns_client *client ) {

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

void dns_receive_response ( dns_client *client ) {

    if ( client->retries >= 10 ) {
        printf ( "Muchos reintentos.\n" );
        exit ( 1 );
    }

    ssize_t received;
    memset ( &client->buf, 0, MAX_BUFSIZE );

    received = recvfrom ( client->descriptor, client->buf, MAX_BUFSIZE, 0, ( struct sockaddr * ) &client->remote,
                          &client->size_remote );

    if ( received != -1 && received != EWOULDBLOCK
         && ( ( client->buf[0] << 8 ) + client->buf[1] == client->msg.tid ) ) {

        client->msg.answerRRCount     = ntohs ( client->buf[6] ) + client->buf[7];
        client->msg.authRRCount       = ntohs ( client->buf[8] ) + client->buf[9];
        client->msg.additionalRRCount = ntohs ( client->buf[10] ) + client->buf[11];
        client->received              = received;
        client->retries               = 0;
        get_list_response ( client );
    } else if ( received == EWOULDBLOCK ) {  // Se retransmite la última trama

        int sent;

        sent = sendto ( client->descriptor, client->buf_backup, client->size_buf, 0,
                        ( struct sockaddr * ) &client->remote, sizeof ( struct sockaddr_in ) );

        if ( sent != client->size_buf )
            printf ( "Error from sendto() in sent_request(): %s \n", strerror ( errno ) );
        client->retries++;
        dns_receive_response ( client );
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

void dns_send_request ( dns_client *client ) {
    int sent;

    sent = sendto ( client->descriptor, client->buf, client->size_buf, 0, ( struct sockaddr * ) &client->remote,
                    sizeof ( struct sockaddr_in ) );

    if ( sent != client->size_buf )
        printf ( "Error from sendto() in sent_request(): %s \n", strerror ( errno ) );

    // Copiamos el buffer por una posible retransmisión
    memset ( &client->buf_backup, 0, 255 );
    memcpy ( &client->buf_backup, &client->buf, 255 );
}

void dns_build_request ( dns_client *client ) {
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

void dns_get_response ( dns_client *client ) {

    dns_build_request ( client );
    dns_send_request ( client );
    dns_receive_response ( client );
}

void dns_init ( dns_client *client, struct gengetopt_args_info *args_info ) {


    if ( args_info->inputs_num > 3 ) {  // Solo nos interesa dos parámetros
        printf ( "Muchos argumentos.\n" );
        exit ( EXIT_FAILURE );
    }

    if ( args_info->inputs_num < 2 ) {

        printf ( "Especifique un nombre de dominio." );
        printf ( " Y dirección inicial.\n" );
        exit ( EXIT_FAILURE );
    }


    if ( !strchr(args_info->inputs[0], '.')) {
        printf ( "Especifique un nombre de dominio con al menos un punto '.' \n" );
        exit(1);
    }

    /* Inicializamos a ceros las estructuras */

    memset ( client, 0, sizeof ( dns_client ) );

    /* Asignamos datos de la estructura dns_client y otros */

    client->addr.sin_family      = AF_INET;
    client->addr.sin_addr.s_addr = INADDR_ANY;
    client->addr.sin_port        = htons ( 0 );
    client->size_addr            = sizeof ( struct sockaddr_in );
    client->server_port          = DEFAULT_SERVER_PORT;

    client->descriptor        = socket ( AF_INET, SOCK_DGRAM, 0 );
    client->start             = true;
    client->end               = false;
    client->msg.questionCount = 1;
    client->timeout.tv_sec    = 2;  // Un segundo

    strcpy ( client->domain, args_info->inputs[0] );

    client->head = malloc ( sizeof ( struct dns_addr ) );

    /* Comprobamos si hay errores */

    if ( !client->head )
        printf ( "Error in malloc() from dns_init(): %s", strerror ( errno ) );

    if ( client->descriptor == -1 )
        printf ( "Error from socket() in dns_init(): %s \n", strerror ( errno ) );

    if ( bind ( client->descriptor, ( struct sockaddr * ) &client->addr, sizeof ( struct sockaddr_in ) ) == -1 )
        printf ( "Error from bind() in dns_init(): %s", strerror ( errno ) );

    /*  Asignamos temporizador de espera en el socket  */

    if ( setsockopt ( client->descriptor, SOL_SOCKET, SO_RCVTIMEO, ( char * ) &client->timeout,
                      sizeof ( client->timeout ) )
         < 0 )
        printf ( "Error from setsockopt() in dns_init(): %s", strerror ( errno ) );

    /* Asignamos datos iniciales de estructura remota */

    client->remote.sin_family = AF_INET;

    //strcpy ( client->domain, "www.ipn.mx");
    inet_pton ( AF_INET, args_info->inputs[1], &client->remote.sin_addr );
    //client->remote.sin_addr.s_addr = inet_addr("148.204.103.2");
    client->remote.sin_port = ntohs ( client->server_port );
    client->size_remote     = sizeof ( struct sockaddr_in );
}

void dns_next_request ( dns_client *client ) {
    // Buscamos un registro tipo A, usaremos el primero

    for ( dns_addr *tmp = client->head; tmp->next != NULL; tmp = tmp->next ) {
        if ( tmp->type == QTYPE_A ) {
            client->remote.sin_addr.s_addr = tmp->addr.s_addr;
            return;
        }
    }
}

void dns_print_response ( dns_client *client ) {
    dns_addr *tmp,*hola;
    char      str[255];
    //memset ( &str2, 0, 255 );


    for ( tmp = client->head; tmp->next != NULL; tmp = tmp->next ) {



        memset ( &str, 0, 255 );
        printf ( "Dominio: %s\n", tmp->domain );
        printf ( "Tipo: %d\n", tmp->type );
        printf ( "Clase: %d\n", tmp->class_internet );
        printf ( "TTL: %d\n", tmp->ttl );
        printf ( "Longitud de datos: %d\n", tmp->data_length );

        switch ( tmp->type ) {
            case QTYPE_NS:
                printf ( "Nombre de dominio: %s\n", tmp->name_server );
                break;
            case QTYPE_CNAME:
                printf ( "Alias: %s\n", tmp->alias );
                break;
            case QTYPE_A:
                inet_ntop ( AF_INET, &tmp->addr, str, INET_ADDRSTRLEN );
                printf ( "IP: %s\n", str );
                break;
            case QTYPE_AAAA:
                inet_ntop ( AF_INET6, &tmp->sin6_addr, str, INET6_ADDRSTRLEN );
                printf ( "IP: %s\n", str );
                break;
        }
        printf ( "\n" );

        if ( tmp->type == QTYPE_A && !strcmp ( client->domain, tmp->domain ) )
            client->end = true;


        if ( tmp->type == QTYPE_CNAME && !strcmp ( client->domain, tmp->domain ) )
            client->end = true;

    }



    if ( (client->flags & 0xff ) == 3) {
        printf("No existe ese nombre de dominio \n");
        exit(0);
    }

}
