#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define HOST "34.246.184.49"
#define PORT 8080

void print_error(char *error)
{
    if (error == NULL)
        return;

    printf("Error: ");
    int len = strlen(error) - 2;
    for (int i = 8; i < len; i++)
        fputc(error[i], stdout);
    printf("\n");
}

// registers a user that provides (username, password) info
void registration()
{
    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    // reading account data
    char username[35], password[35];
    printf("username=");
    fgets(username, 35, stdin);
    username[strlen(username) - 1] = '\0';
    printf("password=");
    fgets(password, 35, stdin);
    password[strlen(password) - 1] = '\0';

    int username_len = strlen(username), passwd_len = strlen(password);

    if (username_len == 0|| passwd_len == 0) {
        printf("Error: Empty creditentials!\n");
        close(sockfd);
        return;
    }

    if (username_len > 30 || passwd_len > 30) {
        printf("Error: Maximum 30 characters for creditentials!\n");
        close(sockfd);
        return;
    }

    if (strchr(username, ' ') ||
            strchr(password, ' ')) {
        printf("Error: No spaces in creditentials!\n");
        close(sockfd);
        return;
    }

    // constructing json object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object =
                json_value_get_object(root_value);
    char **to_json = malloc(sizeof(char *));
    DIE(!to_json, "Malloc failed!\n");
    json_object_set_string(root_object, "username",
                            (const char *)username);
    json_object_set_string(root_object, "password",
                            (const char *)password);

    to_json[0] = json_serialize_to_string_pretty(root_value);

    // sending a POST request to the server
    char *path = "/api/v1/tema/auth/register";
    char *msg;
    msg = compute_post_request(HOST, path, "application/json",
                                to_json, 1, NULL, 0, NULL, 0);

    send_to_server(sockfd, msg);

    // processing response
    char *resp, *error;
    resp = receive_from_server(sockfd);
    if ((error = strstr(resp, "error")) != NULL)
        print_error(error);
    else
        printf("Success: User %s registered!\n", username);

    // freeing allocated data
    json_free_serialized_string(to_json[0]);
    free(to_json);
    json_value_free(root_value);
    free(msg);
    free(resp);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

// creates a session for the client
char *login()
{
    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    // reading account data
    char username[35], password[35];
    printf("username=");
    fgets(username, 35, stdin);
    username[strlen(username) - 1] = '\0';
    printf("password=");
    fgets(password, 35, stdin);
    password[strlen(password) - 1] = '\0';

    int username_len = strlen(username), passwd_len = strlen(password);
    char *ignore = malloc(15);
    DIE(!ignore, "Malloc failed!");
    strcpy(ignore, "Invalid login");

    if (username_len == 0|| passwd_len == 0) {
        printf("Error: Empty creditentials!\n");
        close(sockfd);
        return ignore;
    }

    if (username_len > 30 || passwd_len > 30) {
        printf("Error: Maximum 30 characters for creditentials!\n");
        close(sockfd);
        return ignore;
    }

    if (strchr(username, ' ') ||
            strchr(password, ' ')) {
        printf("Error: No spaces in creditentials!\n");
        close(sockfd);
        return ignore;
    }

    free(ignore);

    // constructing json object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object =
                            json_value_get_object(root_value);
    char **to_json = malloc(sizeof(char *));
    DIE(!to_json, "Malloc failed!\n");
    json_object_set_string(root_object, "username",
                            (const char *)username);
    json_object_set_string(root_object, "password",
                            (const char *)password);
    to_json[0] = json_serialize_to_string_pretty(root_value);

    // sending a POST request to the server
    char *path = "/api/v1/tema/auth/login";
    char *msg;
    msg = compute_post_request(HOST, path, "application/json",
                                to_json, 1, NULL, 0, NULL, 0);
    send_to_server(sockfd, msg);

    // processing response
    char *resp, *copy_cookies = malloc(500), *error;
    DIE(!copy_cookies, "Malloc failed!\n");

    resp = receive_from_server(sockfd);

    if ((error = strstr(resp, "error")) != NULL) {
        strcpy(copy_cookies, "Invalid login");

        print_error(error);
    } else {
        char *cookies = extract_cookies(resp);
        strcpy(copy_cookies, cookies);

        printf("Success: User %s logged in!\n", username);
    }

    // freeing allocated data
    json_free_serialized_string(to_json[0]);
    free(to_json);
    json_value_free(root_value);
    free(msg);
    free(resp);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");

    return copy_cookies;
}

// grants access to the library to the authenticated client
char *enter_library(char *login_cookie)
{
    if (!login_cookie) {
        printf("Error: User not logged in!\n");
        return NULL;
    }
    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    // sending a GET request to the server
    char **send_cookies = malloc(sizeof(char *));
    DIE(!send_cookies, "Malloc failed!\n");

    send_cookies[0] = login_cookie;
    char *path = "/api/v1/tema/library/access";
    char *msg;

    msg = compute_get_request(HOST, path, NULL,
                                send_cookies, 1, NULL, 0);
    send_to_server(sockfd, msg);

    // processing response
    char *resp = receive_from_server(sockfd);

    char *json_resp = basic_extract_json_response(resp);
    char *json_token = strchr(json_resp, ':') + 2;
    char *token = calloc(LINELEN, sizeof(char));

    strncpy(token, json_token, strlen(json_token) - 2);

    char *error;

    if ((error = strstr(resp, "error")) != NULL)
        print_error(error);
    else
        printf("Success: User received access in library!\n");

    // freeing allocated data
    free(msg);
    free(resp);
    free(send_cookies);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");

    return token;
}

// prints all user books in json string format
void get_books(char *token)
{
    if (!token) {
        printf("Error: No access to the library!\n");
        return;
    }

    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    char **additional_header = malloc(sizeof(char *));
    DIE(!additional_header, "Malloc failed!");
    additional_header[0] = calloc(LINELEN, sizeof(char));
    DIE(!additional_header, "Calloc failed!");

    sprintf(additional_header[0], "Authorization: Bearer ");
    sprintf(additional_header[0] +
            strlen(additional_header[0]), "%s", token);

    char *path = "/api/v1/tema/library/books";
    char *msg;

    msg = compute_get_request(HOST, path, NULL, NULL, 0,
                                additional_header, 1);

    send_to_server(sockfd, msg);

    char *resp = receive_from_server(sockfd), *error;

    // printing the list of books or error
    if ((error = strstr(resp, "error")) != NULL) {
        print_error(error);
    } else {
        char *books = NULL;
        books = strstr(resp, "[\{");

        if (books)
            fputs(books, stdout);
        else
            printf("[]");

        printf("\n");
    }

    // freeing allocated data
    free(additional_header[0]);
    free(additional_header);
    free(msg);
    free(resp);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

// Verifies if string is a positive number
bool check_num(char *num, int num_len)
{
    if (num_len > 1 && num[0] == '0')
        return false;

    for (int i = 0; i < num_len; i++)
        if (num[i] < '0' || num[i] > '9')
            return false;

    return true;
}

// returns a json string with the book at a specific id or error
void get_book(char *token)
{
    // reading data
    char id[30];
    printf("id=");
    fgets(id, 30, stdin);
    int id_len = strlen(id);
    id[id_len - 1] = '\0';
    
    if (!check_num(id, id_len - 1)) {
        printf("Error: Invalid id!\n");
        return;
    }


    char path[100];
    sprintf(path, "/api/v1/tema/library/books/");
    sprintf(path + strlen(path), "%s", id);

    if (!token) {
        printf("Error: No access to the library!\n");
        return;
    }

    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    // sending also the JWT token
    char **additional_header = malloc(sizeof(char *));
    DIE(!additional_header, "Malloc failed!");
    additional_header[0] = calloc(LINELEN, sizeof(char));
    DIE(!additional_header[0], "Calloc failed!");

    sprintf(additional_header[0], "Authorization: Bearer ");
    sprintf(additional_header[0] +
            strlen(additional_header[0]), "%s", token);

    char *msg;

    msg = compute_get_request(HOST, path, NULL, NULL, 0,
                                additional_header, 1);

    send_to_server(sockfd, msg);

    char *resp = receive_from_server(sockfd), *error;

    // printing the <id> book details
    if ((error = strstr(resp, "error")) != NULL) {
        print_error(error);
    } else {
        char *book = NULL;
        book = basic_extract_json_response(resp);

        if (book)
            fputs(book, stdout);
        else
            printf("[]");

        printf("\n");
    }

    // freeing allocated data
    free(additional_header[0]);
    free(additional_header);
    free(msg);
    free(resp);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

// reads from stdin the book details
bool read_book(char *title, char *author, char *genre,
                char *page_count, char *publisher)
{
    printf("title=");
    fgets(title, 100, stdin);
    title[strlen(title) - 1] = '\0';
    printf("author=");
    fgets(author, 50, stdin);
    author[strlen(author) - 1] = '\0';
    printf("genre=");
    fgets(genre, 30, stdin);
    genre[strlen(genre) - 1] = '\0';
    printf("publisher=");
    fgets(publisher, 50, stdin);
    publisher[strlen(publisher) - 1] = '\0';
    printf("page_count=");
    fgets(page_count, 30, stdin);
    page_count[strlen(page_count) - 1] = '\0';

    return check_num(page_count, strlen(page_count));
}

// adds a book to the lib or returns error if data is invalid
void add_book(char *token)
{
    // reading book data
    char title[100], author[50], genre[30], page_count[30];
    char publisher[50];

    bool ok;
    ok = read_book(title, author, genre, page_count, publisher);

    if (!ok) {
        printf("Error: page_count not a number!\n");
        return;
    }

    // verifying if user has library access
    if (!token) {
        printf("Error: No access to the library!\n");
        return;
    }

    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    char **additional_header = malloc(sizeof(char *));
    DIE(!additional_header, "Malloc failed!");
    additional_header[0] = calloc(LINELEN, sizeof(char));
    DIE(!additional_header[0], "Calloc failed");

    sprintf(additional_header[0], "Authorization: Bearer ");
    sprintf(additional_header[0] +
            strlen(additional_header[0]), "%s", token);

    // constructing json object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object =
                            json_value_get_object(root_value);

    char **to_json = malloc(sizeof(char *));
    DIE(!to_json, "Malloc failed!\n");

    json_object_set_string(root_object, "title",
                            (const char *)title);
    json_object_set_string(root_object, "author",
                            (const char *)author);
    json_object_set_string(root_object, "genre",
                            (const char *)genre);
    json_object_set_string(root_object, "publisher",
                            (const char *)publisher);
    json_object_set_string(root_object, "page_count",
                            (const char *)page_count);
    to_json[0] = json_serialize_to_string_pretty(root_value);

    // sending a POST request to the server
    char *path = "/api/v1/tema/library/books";
    char *msg;

    msg = compute_post_request(HOST, path, "application/json",
                                to_json, 1, NULL, 0,
                                additional_header, 1);

    send_to_server(sockfd, msg);

    // processing response
    char *resp = receive_from_server(sockfd), *error;

    if ((error = strstr(resp, "error")) != NULL)
        print_error(error);
    else
        printf("Success: Book registered!\n");

    // freeing allocated data
    json_free_serialized_string(to_json[0]);
    free(to_json);
    json_value_free(root_value);
    free(msg);
    free(resp);
    free(additional_header[0]);
    free(additional_header);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

// removes a book from the library or returns error
void delete_book(char *token)
{
    // reading data
    char id[30];

    printf("id=");
    fgets(id, 30, stdin);
    id[strlen(id) - 1] = '\0';

    if (!check_num(id, strlen(id))) {
        printf("Error: id not a number!\n");
        return;
    }

    char path[100];

    sprintf(path, "/api/v1/tema/library/books/");
    sprintf(path + strlen(path), "%s", id);


    // verifying if user has library access
    if (!token) {
        printf("Error: No access to the library!\n");
        return;
    }

    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    char **additional_header = malloc(sizeof(char *));
    DIE(!additional_header, "Malloc failed!");
    additional_header[0] = calloc(LINELEN, sizeof(char));
    DIE(!additional_header[0], "Calloc failed!");

    sprintf(additional_header[0], "Authorization: Bearer ");
    sprintf(additional_header[0] +
            strlen(additional_header[0]), "%s", token);

    // sending a DELETE request to the server
    char *msg;

    msg = compute_delete_request(HOST, path,
                                    additional_header, 1);

    send_to_server(sockfd, msg);

    // processing response
    char *resp = receive_from_server(sockfd), *error;

    if ((error = strstr(resp, "error")) != NULL)
        print_error(error);
    else
        printf("Success: Book deleted!\n");

    // freeing allocated data
    free(msg);
    free(resp);
    free(additional_header[0]);
    free(additional_header);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

// user logout request
void logout_request(char *login_cookie)
{
    if (!login_cookie) {
        printf("Error: Client not authenticated!\n");
        return;
    }

    int sockfd = open_connection(HOST, PORT, AF_INET,
                                    SOCK_STREAM, 0);

    // sending a GET request to the server
    char **send_cookies = malloc(sizeof(char *));
    DIE(!send_cookies, "Malloc failed!\n");

    send_cookies[0] = login_cookie;

    char *path = "/api/v1/tema/auth/logout";
    char *msg;

    msg = compute_get_request(HOST, path, NULL, send_cookies,
                                1, NULL, 0);

    send_to_server(sockfd, msg);

    // processing response
    char *resp = receive_from_server(sockfd), *error;

    if ((error = strstr(resp, "error")) != NULL)
        print_error(error);
    else
        printf("Success: User logged out!\n");

    // free allocated data
    free(msg);
    free(resp);
    free(send_cookies);

    if (close(sockfd) < 0)
        printf("Error: Could not close the connection!\n");
}

int main()
{
    char interact[LINELEN];
    char *login_cookie = NULL, *entry_token = NULL;
    bool logout = true;

    // menu with input from stdin
    while (true) {
        if (!fgets(interact, LINELEN, stdin))
            break;

        // one connection per command open - close
        if (strcmp(interact, "register\n") == 0) {
            if (logout == true) {
                registration();
            } else {
                printf("username=");
                fgets(interact, 30, stdin);
                printf("password=");
                fgets(interact, 30, stdin);
                printf("Error: the current user did not log out!\n");
            }
        } else if (strcmp(interact, "exit\n") == 0) {
            break;
        } else if (strcmp(interact, "login\n") == 0) {
            if (!logout) {
                printf("username=");
                fgets(interact, 30, stdin);
                printf("password=");
                fgets(interact, 30, stdin);
                printf("Error: the current user did not log out!\n");
                continue;
            }

            login_cookie = login();
            if (strncmp(login_cookie, "Invalid login", 13) == 0) {
                free(login_cookie);
                login_cookie = NULL;
                logout = true;
            } else {
                logout = false;
            }
        } else if (strcmp(interact, "enter_library\n") == 0) {
            entry_token = enter_library(login_cookie);
        } else if (strcmp(interact, "get_books\n") == 0) {
            get_books(entry_token);
        } else if (strcmp(interact, "get_book\n") == 0) {
            get_book(entry_token);
        } else if (strcmp(interact, "add_book\n") == 0) {
            add_book(entry_token);
        } else if (strcmp(interact, "delete_book\n") == 0) {
            delete_book(entry_token);
        } else if (strcmp(interact, "logout\n") == 0) {
            logout_request(login_cookie);
            logout = true;

            free(login_cookie);
            login_cookie = NULL;
            free(entry_token);
            entry_token = NULL;
        } else {
            printf("Error: Invalid command!\n");
        }
    }

    // free allocated memory
    if (login_cookie)
        free(login_cookie);
    if (entry_token)
        free(entry_token);

    return 0;
}
