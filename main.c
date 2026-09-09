#include <curl/curl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assets_cacert_pem.h"

#define APP_NAME "PLDMGR Install & Update"

#define RELEASE_API \
    "https://api.github.com/repos/itsPLK/ps5-payload-manager/releases/latest"

#define RELEASE_PREFIX \
    "https://github.com/itsPLK/ps5-payload-manager/releases/download/"

#define AUTOLOADER_DIR "/data/ps5_autoloader"

#define PLDMGR_FILE AUTOLOADER_DIR "/pldmgr.elf"
#define PLDMGR_TEMP AUTOLOADER_DIR "/pldmgr.elf.tmp"
#define PLDMGR_BACKUP AUTOLOADER_DIR "/pldmgr.elf.bak"

#define AUTOLOAD_FILE AUTOLOADER_DIR "/autoload.txt"
#define AUTOLOAD_TEMP AUTOLOADER_DIR "/autoload.txt.tmp"
#define AUTOLOAD_BACKUP AUTOLOADER_DIR "/autoload.txt.bak"

#define VERSION_FILE AUTOLOADER_DIR "/pldmgr.version"
#define VERSION_TEMP AUTOLOADER_DIR "/pldmgr.version.tmp"
#define VERSION_BACKUP AUTOLOADER_DIR "/pldmgr.version.bak"

#define MIN_ELF_SIZE (64 * 1024)
#define MAX_ELF_SIZE (32 * 1024 * 1024)

typedef struct {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(
    int device,
    notify_request_t *req,
    size_t size,
    int blocking
);

typedef struct {
    char *data;
    size_t size;
} memory_buffer_t;


/* ============================================================
   NOTIFICACIONES
   ============================================================ */

static void notify(const char *fmt, ...)
{
    notify_request_t req;
    va_list args;

    memset(&req, 0, sizeof(req));

    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);

    sceKernelSendNotificationRequest(
        0,
        &req,
        sizeof(req),
        0
    );
}


/* ============================================================
   UTILIDADES DE ARCHIVO
   ============================================================ */

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void cleanup_temp_files(void)
{
    remove(PLDMGR_TEMP);
    remove(AUTOLOAD_TEMP);
    remove(VERSION_TEMP);
}

static int read_small_text(
    const char *path,
    char *out,
    size_t out_size
)
{
    FILE *fp;
    size_t n;

    if (!out || out_size == 0) {
        return -1;
    }

    out[0] = '\0';

    fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    n = fread(out, 1, out_size - 1, fp);
    fclose(fp);

    out[n] = '\0';

    while (
        n > 0 &&
        (
            out[n - 1] == '\n' ||
            out[n - 1] == '\r' ||
            out[n - 1] == ' ' ||
            out[n - 1] == '\t'
        )
    ) {
        out[n - 1] = '\0';
        n--;
    }

    return 0;
}

static int write_text_file(
    const char *path,
    const char *text,
    mode_t mode
)
{
    FILE *fp;
    size_t len;
    int ok;

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    len = strlen(text);
    ok = fwrite(text, 1, len, fp) == len;

    if (ok && fflush(fp) != 0) {
        ok = 0;
    }

    if (ok && fsync(fileno(fp)) != 0) {
        ok = 0;
    }

    if (fclose(fp) != 0) {
        ok = 0;
    }

    if (!ok) {
        remove(path);
        return -1;
    }

    chmod(path, mode);
    return 0;
}


/* ============================================================
   CURL / HTTPS
   ============================================================ */

static size_t write_memory(
    void *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
)
{
    memory_buffer_t *buffer = (memory_buffer_t *)userdata;
    size_t total = size * nmemb;
    char *new_data;

    new_data = realloc(
        buffer->data,
        buffer->size + total + 1
    );

    if (!new_data) {
        return 0;
    }

    buffer->data = new_data;

    memcpy(
        buffer->data + buffer->size,
        ptr,
        total
    );

    buffer->size += total;
    buffer->data[buffer->size] = '\0';

    return total;
}

static size_t write_file(
    void *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
)
{
    return fwrite(
        ptr,
        size,
        nmemb,
        (FILE *)userdata
    );
}

static int setup_curl(
    CURL *curl,
    const char *url
)
{
    struct curl_blob ca_blob;

    memset(&ca_blob, 0, sizeof(ca_blob));

    ca_blob.data = hk_cacert_pem;
    ca_blob.len = hk_cacert_pem_len;
    ca_blob.flags = CURL_BLOB_COPY;

    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
        return -1;
    }

    curl_easy_setopt(
        curl,
        CURLOPT_USERAGENT,
        "HiddenKernel-PLDMGR-Install-Update/1.0"
    );

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180L);

    /* HTTPS verification enabled. */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);

    return 0;
}

static int request_ok(
    CURL *curl,
    CURLcode result
)
{
    long http_code = 0;

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &http_code
    );

    return (
        result == CURLE_OK &&
        http_code >= 200 &&
        http_code < 300
    );
}


/* ============================================================
   DESCARGAS
   ============================================================ */

static char *download_text(const char *url)
{
    CURL *curl;
    memory_buffer_t buffer;
    struct curl_slist *headers;
    CURLcode result;
    int ok;

    curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    memset(&buffer, 0, sizeof(buffer));

    if (setup_curl(curl, url) != 0) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    headers = NULL;

    headers = curl_slist_append(
        headers,
        "Accept: application/vnd.github+json"
    );

    headers = curl_slist_append(
        headers,
        "X-GitHub-Api-Version: 2022-11-28"
    );

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

    result = curl_easy_perform(curl);
    ok = request_ok(curl, result);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!ok) {
        free(buffer.data);
        return NULL;
    }

    return buffer.data;
}

static int download_file(
    const char *url,
    const char *destination
)
{
    FILE *file;
    CURL *curl;
    CURLcode result;
    int ok;

    file = fopen(destination, "wb");
    if (!file) {
        return -1;
    }

    curl = curl_easy_init();

    if (!curl) {
        fclose(file);
        remove(destination);
        return -1;
    }

    if (setup_curl(curl, url) != 0) {
        curl_easy_cleanup(curl);
        fclose(file);
        remove(destination);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

    result = curl_easy_perform(curl);
    ok = request_ok(curl, result);

    curl_easy_cleanup(curl);

    if (fflush(file) != 0) {
        ok = 0;
    }

    if (fsync(fileno(file)) != 0) {
        ok = 0;
    }

    if (fclose(file) != 0) {
        ok = 0;
    }

    if (!ok) {
        remove(destination);
        return -1;
    }

    return 0;
}


/* ============================================================
   PARSEO DE RELEASE OFICIAL
   ============================================================ */

static int starts_with(
    const char *text,
    const char *prefix
)
{
    return strncmp(
        text,
        prefix,
        strlen(prefix)
    ) == 0;
}

static int ends_with(
    const char *text,
    const char *suffix
)
{
    size_t text_length = strlen(text);
    size_t suffix_length = strlen(suffix);

    if (suffix_length > text_length) {
        return 0;
    }

    return strcmp(
        text + text_length - suffix_length,
        suffix
    ) == 0;
}

static int find_json_string(
    const char *json,
    const char *key,
    char *output,
    size_t output_size
)
{
    char needle[128];
    const char *cursor;
    const char *colon;
    const char *start;
    const char *end;
    size_t length;

    snprintf(
        needle,
        sizeof(needle),
        "\"%s\"",
        key
    );

    cursor = strstr(json, needle);
    if (!cursor) {
        return -1;
    }

    colon = strchr(cursor, ':');
    if (!colon) {
        return -1;
    }

    start = strchr(colon, '"');
    if (!start) {
        return -1;
    }

    start++;

    end = strchr(start, '"');
    if (!end) {
        return -1;
    }

    length = (size_t)(end - start);

    if (
        length == 0 ||
        length >= output_size
    ) {
        return -1;
    }

    memcpy(output, start, length);
    output[length] = '\0';

    return 0;
}

static int find_pldmgr_url(
    const char *json,
    char *output,
    size_t output_size
)
{
    const char *cursor = json;

    while (
        (
            cursor = strstr(
                cursor,
                "\"browser_download_url\""
            )
        ) != NULL
    ) {
        const char *colon;
        const char *start;
        const char *end;
        size_t length;

        colon = strchr(cursor, ':');
        if (!colon) {
            return -1;
        }

        start = strchr(colon, '"');
        if (!start) {
            return -1;
        }

        start++;

        end = strchr(start, '"');
        if (!end) {
            return -1;
        }

        length = (size_t)(end - start);

        if (
            length > 0 &&
            length < output_size &&
            length < 1024
        ) {
            char candidate[1024];

            memcpy(candidate, start, length);
            candidate[length] = '\0';

            if (
                starts_with(
                    candidate,
                    RELEASE_PREFIX
                ) &&
                strstr(
                    candidate,
                    "pldmgr"
                ) != NULL &&
                ends_with(
                    candidate,
                    ".elf"
                )
            ) {
                memcpy(
                    output,
                    candidate,
                    length + 1
                );

                return 0;
            }
        }

        cursor = end + 1;
    }

    return -1;
}


/* ============================================================
   VALIDACIONES LOCALES
   ============================================================ */

static int validate_elf(const char *path)
{
    struct stat st;
    FILE *file;
    unsigned char magic[4];
    size_t read_count;

    if (stat(path, &st) != 0) {
        return -1;
    }

    if (
        st.st_size < MIN_ELF_SIZE ||
        st.st_size > MAX_ELF_SIZE
    ) {
        return -1;
    }

    file = fopen(path, "rb");

    if (!file) {
        return -1;
    }

    read_count = fread(
        magic,
        1,
        sizeof(magic),
        file
    );

    fclose(file);

    if (read_count != sizeof(magic)) {
        return -1;
    }

    if (
        magic[0] != 0x7F ||
        magic[1] != 'E' ||
        magic[2] != 'L' ||
        magic[3] != 'F'
    ) {
        return -1;
    }

    return 0;
}

static int autoload_is_correct(void)
{
    char content[128];

    if (
        read_small_text(
            AUTOLOAD_FILE,
            content,
            sizeof(content)
        ) != 0
    ) {
        return 0;
    }

    return (
        strcmp(
            content,
            "!3000\npldmgr.elf"
        ) == 0
    );
}


/* ============================================================
   PREPARAR ARCHIVOS TEMPORALES
   ============================================================ */

static int create_autoload_temp(void)
{
    return write_text_file(
        AUTOLOAD_TEMP,
        "!3000\npldmgr.elf\n",
        0644
    );
}

static int create_version_temp(
    const char *version
)
{
    char buffer[256];

    snprintf(
        buffer,
        sizeof(buffer),
        "%s\n",
        version
    );

    return write_text_file(
        VERSION_TEMP,
        buffer,
        0644
    );
}


/* ============================================================
   BACKUP / ROLLBACK
   ============================================================ */

static int backup_file(
    const char *original,
    const char *backup,
    int *had_original
)
{
    *had_original = 0;

    remove(backup);

    if (!file_exists(original)) {
        return 0;
    }

    if (
        rename(
            original,
            backup
        ) != 0
    ) {
        return -1;
    }

    *had_original = 1;
    return 0;
}

static void restore_backup(
    const char *original,
    const char *backup,
    int had_original
)
{
    remove(original);

    if (
        had_original &&
        file_exists(backup)
    ) {
        rename(backup, original);
    }
}

static int install_files(void)
{
    int had_pldmgr = 0;
    int had_autoload = 0;
    int had_version = 0;

    if (
        backup_file(
            PLDMGR_FILE,
            PLDMGR_BACKUP,
            &had_pldmgr
        ) != 0
    ) {
        return -1;
    }

    if (
        backup_file(
            AUTOLOAD_FILE,
            AUTOLOAD_BACKUP,
            &had_autoload
        ) != 0
    ) {
        restore_backup(
            PLDMGR_FILE,
            PLDMGR_BACKUP,
            had_pldmgr
        );

        return -1;
    }

    if (
        backup_file(
            VERSION_FILE,
            VERSION_BACKUP,
            &had_version
        ) != 0
    ) {
        restore_backup(
            PLDMGR_FILE,
            PLDMGR_BACKUP,
            had_pldmgr
        );

        restore_backup(
            AUTOLOAD_FILE,
            AUTOLOAD_BACKUP,
            had_autoload
        );

        return -1;
    }

    if (
        rename(
            PLDMGR_TEMP,
            PLDMGR_FILE
        ) != 0
    ) {
        goto rollback;
    }

    chmod(PLDMGR_FILE, 0755);

    if (
        rename(
            AUTOLOAD_TEMP,
            AUTOLOAD_FILE
        ) != 0
    ) {
        goto rollback;
    }

    chmod(AUTOLOAD_FILE, 0644);

    if (
        rename(
            VERSION_TEMP,
            VERSION_FILE
        ) != 0
    ) {
        goto rollback;
    }

    chmod(VERSION_FILE, 0644);

    remove(PLDMGR_BACKUP);
    remove(AUTOLOAD_BACKUP);
    remove(VERSION_BACKUP);

    return 0;

rollback:

    restore_backup(
        PLDMGR_FILE,
        PLDMGR_BACKUP,
        had_pldmgr
    );

    restore_backup(
        AUTOLOAD_FILE,
        AUTOLOAD_BACKUP,
        had_autoload
    );

    restore_backup(
        VERSION_FILE,
        VERSION_BACKUP,
        had_version
    );

    return -1;
}


/* ============================================================
   MAIN
   ============================================================ */

int main(
    int argc,
    char **argv
)
{
    char *release_json;
    char latest_version[128];
    char installed_version[128];
    char download_url[1024];
    int needs_install = 0;

    (void)argc;
    (void)argv;

    notify(
        "%s: comprobando actualizaciones...",
        APP_NAME
    );

    /*
        Si la carpeta no existe, se crea.
    */
    if (
        mkdir(
            AUTOLOADER_DIR,
            0777
        ) != 0 &&
        errno != EEXIST
    ) {
        notify(
            "%s: no se pudo crear %s",
            APP_NAME,
            AUTOLOADER_DIR
        );

        return -1;
    }

    cleanup_temp_files();

    if (
        curl_global_init(
            CURL_GLOBAL_ALL
        ) != 0
    ) {
        notify(
            "%s: error inicializando red.",
            APP_NAME
        );

        return -1;
    }

    /*
        Consulta SIEMPRE la última release oficial.
    */
    release_json = download_text(
        RELEASE_API
    );

    if (!release_json) {
        notify(
            "%s: no se pudo consultar GitHub.",
            APP_NAME
        );

        curl_global_cleanup();
        return -1;
    }

    memset(
        latest_version,
        0,
        sizeof(latest_version)
    );

    memset(
        download_url,
        0,
        sizeof(download_url)
    );

    if (
        find_json_string(
            release_json,
            "tag_name",
            latest_version,
            sizeof(latest_version)
        ) != 0
    ) {
        notify(
            "%s: no se pudo detectar la versión disponible.",
            APP_NAME
        );

        free(release_json);
        curl_global_cleanup();
        return -1;
    }

    if (
        find_pldmgr_url(
            release_json,
            download_url,
            sizeof(download_url)
        ) != 0
    ) {
        notify(
            "%s: no se encontró pldmgr.elf en la release oficial.",
            APP_NAME
        );

        free(release_json);
        curl_global_cleanup();
        return -1;
    }

    free(release_json);

    installed_version[0] = '\0';

    if (
        read_small_text(
            VERSION_FILE,
            installed_version,
            sizeof(installed_version)
        ) != 0
    ) {
        installed_version[0] = '\0';
    }

    /*
        Instalamos si:
        - no existe pldmgr.elf;
        - el ELF local no es válido;
        - no existe el marcador de versión;
        - la versión oficial ha cambiado;
        - autoload.txt falta o no contiene nuestra configuración.
    */
    if (!file_exists(PLDMGR_FILE)) {
        needs_install = 1;
    }

    if (
        !needs_install &&
        validate_elf(PLDMGR_FILE) != 0
    ) {
        needs_install = 1;
    }

    if (
        !needs_install &&
        installed_version[0] == '\0'
    ) {
        needs_install = 1;
    }

    if (
        !needs_install &&
        strcmp(
            installed_version,
            latest_version
        ) != 0
    ) {
        needs_install = 1;
    }

    if (
        !needs_install &&
        !autoload_is_correct()
    ) {
        needs_install = 1;
    }

    if (!needs_install) {
        notify(
            "%s: ya tienes la última versión (%s).",
            APP_NAME,
            latest_version
        );

        curl_global_cleanup();
        return 0;
    }

    notify(
        "%s: instalando %s...",
        APP_NAME,
        latest_version
    );

    if (
        download_file(
            download_url,
            PLDMGR_TEMP
        ) != 0
    ) {
        notify(
            "%s: error descargando Payload Manager.",
            APP_NAME
        );

        cleanup_temp_files();
        curl_global_cleanup();
        return -1;
    }

    if (
        validate_elf(
            PLDMGR_TEMP
        ) != 0
    ) {
        notify(
            "%s: el archivo descargado no es un ELF válido.",
            APP_NAME
        );

        cleanup_temp_files();
        curl_global_cleanup();
        return -1;
    }

    if (
        create_autoload_temp()
        != 0
    ) {
        notify(
            "%s: error preparando autoload.txt.",
            APP_NAME
        );

        cleanup_temp_files();
        curl_global_cleanup();
        return -1;
    }

    if (
        create_version_temp(
            latest_version
        ) != 0
    ) {
        notify(
            "%s: error preparando la versión instalada.",
            APP_NAME
        );

        cleanup_temp_files();
        curl_global_cleanup();
        return -1;
    }

    if (
        install_files()
        != 0
    ) {
        notify(
            "%s: error instalando; se intentó restaurar la copia anterior.",
            APP_NAME
        );

        cleanup_temp_files();
        curl_global_cleanup();
        return -1;
    }

    notify(
        "%s: %s instalado correctamente.",
        APP_NAME,
        latest_version
    );

    notify(
        "autoload.txt configurado con Payload Manager."
    );

    curl_global_cleanup();
    return 0;
}
