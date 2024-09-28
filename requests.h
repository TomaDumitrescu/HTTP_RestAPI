#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(char *host, char *url, char *query_params,
                            char **cookies, int cookies_count,
                            char **additional_headers, int additional_count);

// computes and returns a POST request string (cookies = NULL if not needed)
char *compute_post_request(char *host, char *url, char* content_type,
                            char **body_data, int body_data_fields_count,
                            char **cookies, int cookies_count,
                            char **additional_headers, int additional_count);

// computes and returns a simple DELETE request string
char *compute_delete_request(char *host, char *url, char **additional_headers,
                                int additional_count);

#endif
