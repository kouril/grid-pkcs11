#include "locl.h"

int
get_myproxy_creds(char *server, char *username, char *password,
                  char **creds)
{
    myproxy_socket_attrs_t *socket_attrs = NULL;
    myproxy_request_t      *client_request = NULL;
    myproxy_response_t     *server_response = NULL;
    char *request_buffer = NULL;
    char creds_file[MAXPATHLEN];
    int ret, requestlen;

    verror_clear();

    socket_attrs = malloc(sizeof(*socket_attrs));
    if (socket_attrs == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto end;
    }
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    if (client_request == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto end;
    }
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    if (server_response == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto end;
    }
    memset(server_response, 0, sizeof(*server_response));

    socket_attrs->psport = MYPROXY_SERVER_PORT;
    socket_attrs->pshost = strdup(server);
    if (socket_attrs->pshost == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto end;
    }

    ret = myproxy_init_client(socket_attrs);
    if (ret < 0) {
	st_logf("Error contacting MyProxy server %s: %s\n",
		socket_attrs->pshost, verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);
    ret = myproxy_authenticate_init(socket_attrs, NULL);
    if (ret < 0) {
	st_logf("Error authenticating MyProxy server %s: %s\n",
		socket_attrs->pshost, verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    client_request->version = strdup(MYPROXY_VERSION);
    client_request->command_type = MYPROXY_RETRIEVE_CERT;
    strncpy(client_request->passphrase, password, sizeof(client_request->passphrase));
    client_request->username = strdup(username);

    requestlen = myproxy_serialize_request_ex(client_request, &request_buffer);
    if (requestlen < 0) {
	st_logf("Error preparing MyProxy request: %s\n",
		verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    ret = myproxy_send(socket_attrs, request_buffer, requestlen);
    free(request_buffer);
    if (ret < 0) {
	st_logf("Error sending MyProxy request: %s\n",
		verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    ret = myproxy_recv_response_ex(socket_attrs, server_response,
				   client_request);
    if (ret != 0) {
	st_logf("Error receiving MyProxy response: %s\n",
		verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    ret = myproxy_accept_credentials(socket_attrs, creds_file,
				     sizeof(creds_file));
    if (ret < 0) {
	st_logf("Error receiving credentials: %s\n",
		verror_get_string());
	ret = CKR_GENERAL_ERROR;
	goto end;
    }

    *creds = strdup(creds_file);
    if (*creds == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto end;
    }

    ret = 0;

end:
    if (socket_attrs && socket_attrs->socket_fd)
	close(socket_attrs->socket_fd);
    myproxy_free(socket_attrs, client_request, server_response);
    verror_clear();

    return ret;
}
