#include "esp_wol.h"
#include <ctype.h>
#include "cJSON.h"

#define MAX_SCAN_AP_NUMBER 32
#define SAVED_WLAN_FILEPATH "/spiffs/saved_wlan.json"
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define OTA_BUF_SIZE 1024

static EventGroupHandle_t wifi_event_group;
static char connected_ssid[33] = { 0 };
static char ipv4str[16] = { 0 };
static char ipv6str[64] = { 0 };
static cJSON *saved_wlan = NULL;
static int udp_socket = 0;
static const char *TAG_WEB = "Web Server";
static const char *TAG_AP = "WiFi SoftAP";
static const char *TAG_STA = "WiFi Sta";
static const char *TAG_OTA = "OTA";
static esp_netif_t *esp_netif_ap = NULL;
static esp_netif_t *esp_netif_sta = NULL;

/* alloc dns for ap client */
static void softap_set_dns_addr(esp_netif_t *esp_netif_ap, esp_netif_t *esp_netif_sta)
{
    esp_netif_dns_info_t dns;
    esp_netif_get_dns_info(esp_netif_sta, ESP_NETIF_DNS_MAIN, &dns);
    uint8_t dhcps_offer_option = 0x02;
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(esp_netif_ap));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(esp_netif_ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_offer_option, sizeof(dhcps_offer_option)));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(esp_netif_ap, ESP_NETIF_DNS_MAIN, &dns));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_start(esp_netif_ap));
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *) event_data;
        ESP_LOGI(TAG_AP, "Station "MACSTR" joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *) event_data;
        ESP_LOGI(TAG_AP, "Station "MACSTR" left, AID=%d, reason:%d",
                 MAC2STR(event->mac), event->aid, event->reason);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG_STA, "Station started");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        // connect to ap
        if (wifi_event_group) xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        wifi_event_sta_connected_t *event = (wifi_event_sta_connected_t *) event_data;
        memcpy(connected_ssid, event->ssid, event->ssid_len);
        connected_ssid[event->ssid_len] = '\0';
        ESP_LOGI(TAG_STA, "connect to \"%s\", channel: %u", connected_ssid, event->channel);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        // disconnect from ap
        if (wifi_event_group) xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
        // wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *) event_data;
        ESP_LOGI(TAG_STA, "disconnected from \"%s\"", connected_ssid);
        connected_ssid[0] = '\0';
        ipv4str[0] = '\0';
        ipv6str[0] = '\0';
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        sprintf(ipv4str, IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG_STA, "Got IP: %s", ipv4str);
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        esp_netif_create_ip6_linklocal(netif);
        softap_set_dns_addr(esp_netif_ap,esp_netif_sta);
    }  else if (event_base == IP_EVENT && event_id == IP_EVENT_GOT_IP6) {
        ip_event_got_ip6_t* event = (ip_event_got_ip6_t*) event_data;
        sprintf(ipv6str, IPV6STR, IPV62STR(event->ip6_info.ip));
        ESP_LOGI(TAG_STA, "Got IP6: %s", ipv6str);
    }
}

/* Initialize soft AP */
esp_netif_t *wifi_init_softap(void)
{
    esp_netif_ap = esp_netif_create_default_wifi_ap();

    wifi_config_t wifi_ap_config = {
        .ap = {
            .ssid = CONFIG_ESP_WIFI_AP_SSID,
            .ssid_len = strlen(CONFIG_ESP_WIFI_AP_SSID),
            .channel = CONFIG_ESP_WIFI_AP_CHANNEL,
            .password = CONFIG_ESP_WIFI_AP_PASSWORD,
            .max_connection = CONFIG_ESP_MAX_STA_CONN_AP,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    if (strlen(CONFIG_ESP_WIFI_AP_PASSWORD) == 0) {
        wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));
    ESP_LOGI(TAG_AP, "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             CONFIG_ESP_WIFI_AP_SSID, CONFIG_ESP_WIFI_AP_PASSWORD, CONFIG_ESP_WIFI_AP_CHANNEL);

    return esp_netif_ap;
}

static esp_netif_t *wifi_init_sta(void) {
    return esp_netif_create_default_wifi_sta();
}

static void wifi_init()
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Register Event handler */
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_GOT_IP6,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    /*Initialize WiFi */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    cfg.nvs_enable = false;
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    /* Initialize AP */
    ESP_LOGI(TAG_AP, "ESP_WIFI_MODE_AP");
    esp_netif_t *esp_netif_ap = wifi_init_softap();

    /* Initialize STA */
    ESP_LOGI(TAG_STA, "ESP_WIFI_MODE_STA");
    esp_netif_t *esp_netif_sta = wifi_init_sta();

    /* Start WiFi */
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Set sta as the default interface */
    esp_netif_set_default_netif(esp_netif_sta);

    /* Enable napt on the AP netif */
    if (esp_netif_napt_enable(esp_netif_ap) != ESP_OK) {
        ESP_LOGE(TAG_STA, "NAPT not enabled on the netif: %p", esp_netif_ap);
    }
}

static void create_udp_socket() {
    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int yes = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
}

static void send_magic_packet(const char *mac_str) {
    uint8_t mac[6];
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        ESP_LOGE(TAG_WEB, "Invalid MAC format, %s", mac_str);
        return;
    }

    uint8_t packet[102];
    memset(packet, 0xFF, 6);
    for (int i = 1; i <= 16; ++i) {
        memcpy(&packet[i * 6], mac, 6);
    }

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr.s_addr = inet_addr("255.255.255.255")
    };
    sendto(udp_socket, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    ESP_LOGI(TAG_WEB, "Magic packet sent to %s", mac_str);
}

static esp_err_t httpd_send_file_with_chunk(httpd_req_t* req, const char* filepath) {
    FILE* f = fopen(filepath, "r");
    if (f == NULL) {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    static char chunk[1024];
    size_t read_bytes;
    while ((read_bytes = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        httpd_resp_send_chunk(req, chunk, read_bytes);
    }
    httpd_resp_send_chunk(req, NULL, 0);

    fclose(f);
    return ESP_OK;
}

static esp_err_t fast_scan(uint16_t *number, wifi_ap_record_t *ap_records) {
    static wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 30,
        .scan_time.active.max = 60
    };
    uint16_t total_ap_num = 0;
    for (int ch = 0; ch < 3; ++ch) {
        if (total_ap_num >= *number) break;
        scan_config.channel = (ch == 0) ? 1 : (ch == 1) ? 6 : 11;
        if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
            ESP_LOGE(TAG_WEB, "fast scan failed, channel: %d", ch);
            return ESP_FAIL;
        }
        uint16_t ap_num = 0;
        esp_wifi_scan_get_ap_num(&ap_num);
        if (!ap_num) {
            ESP_LOGI(TAG_WEB, "fast scan channel %d with 0 wlan", ch);
            continue;
        }
        if (ap_num > *number - total_ap_num) ap_num = *number - total_ap_num;
        esp_wifi_scan_get_ap_records(&ap_num, &ap_records[total_ap_num]);
        total_ap_num += ap_num;
    }
    *number = total_ap_num;
    return ESP_OK;
}

static esp_err_t full_scan(uint16_t *number, wifi_ap_record_t *ap_records) {
    static wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = false,
    };
    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        ESP_LOGE(TAG_WEB, "full scan failed");
        return ESP_FAIL;
    }
    uint16_t total_ap_num = 0;
    esp_wifi_scan_get_ap_num(&total_ap_num);
    if (!total_ap_num) {
        ESP_LOGI(TAG_WEB, "full scan with 0 wlan");
        return ESP_OK;
    }
    if (total_ap_num > *number) total_ap_num = *number;
    esp_wifi_scan_get_ap_records(&total_ap_num, &ap_records[total_ap_num]);
    return ESP_OK;
}

static esp_err_t status_get_handler(httpd_req_t *req) {
    // construct JSON str for response
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "ipv4_addr", cJSON_CreateString(ipv4str));
    cJSON_AddItemToObject(root, "ipv6_addr", cJSON_CreateString(ipv6str));
    // generate json string
    char *json_str = cJSON_PrintUnformatted(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_get_handler(httpd_req_t *req) {
    // scan ap
    static wifi_ap_record_t ap_records[MAX_SCAN_AP_NUMBER];
    uint16_t total_ap_num = MAX_SCAN_AP_NUMBER;
    if (
#ifndef ESP_WIFI_STA_SCAN_FULL
        fast_scan(&total_ap_num, ap_records)
#else
        full_scan(&total_ap_num, ap_records)
#endif
        != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{}");
        return ESP_FAIL;
    }

    // construct JSON str for response
    cJSON *root = cJSON_CreateObject();
    // connected wlan
    cJSON *connected = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "connected", connected);
    bool has_connected = false;
    static wifi_ap_record_t connected_ap_record;
    if (esp_wifi_sta_get_ap_info(&connected_ap_record) == ESP_OK) {
        has_connected = true;
        cJSON *ap_info = cJSON_CreateObject();
        cJSON_AddItemToObject(connected, (char *) connected_ap_record.ssid, ap_info);
        cJSON_AddItemToObject(ap_info, "rssi", cJSON_CreateNumber(connected_ap_record.rssi));
        cJSON_AddItemToObject(ap_info, "lock", cJSON_CreateNumber(connected_ap_record.authmode != WIFI_AUTH_OPEN? 2: 1));
    }
    // saved wlan
    cJSON *saved = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "saved", saved);
    // nearby wlan
    cJSON *nearby = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "nearby", nearby);

    // classify
    static wifi_ap_record_t *ssid_set[MAX_SCAN_AP_NUMBER] = { NULL };
    int ssid_set_idx = 0;
    for (int i = 0; i < total_ap_num; ++i) {
        wifi_ap_record_t *ap_record = &ap_records[i];
        // skip hidden wlan ssid
        if (!strlen((char *) ap_record->ssid))
            continue;

        // skip connected wlan ssid
        if (has_connected && !strcmp((const char *) connected_ap_record.ssid, (const char *) ap_record->ssid)) {
            continue;
            if (ap_record->rssi > connected_ap_record.rssi)
                connected_ap_record.rssi = ap_record->rssi;
        }

        // skip repate wlan ssid
        bool isRepate = false;
        for (int j = 0; j < ssid_set_idx; ++j) {
            if (!strcmp((char *) ssid_set[j]->ssid, (char *) ap_record->ssid)) {
                isRepate = true;
                if (ap_record->rssi > ssid_set[j]->rssi)
                    ssid_set[j]->rssi = ap_record->rssi;
                break;
            }
        }
        if (isRepate)
            continue;
        ssid_set[ssid_set_idx++] = ap_record;

        // fill json object
        cJSON *ap_info = cJSON_CreateObject();
        cJSON_AddItemToObject(ap_info, "rssi", cJSON_CreateNumber(ap_record->rssi));
        cJSON_AddItemToObject(ap_info, "lock", cJSON_CreateNumber(ap_record->authmode != WIFI_AUTH_OPEN? 2: 1));
        if (cJSON_GetObjectItem(saved_wlan, (char *) ap_record->ssid)) {
            cJSON_AddItemToObject(saved, (char *) ap_record->ssid, ap_info);
        } else {
            cJSON_AddItemToObject(nearby, (char *) ap_record->ssid, ap_info);
        }
    }
    // generate json string
    char *json_str = cJSON_PrintUnformatted(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    cJSON_Delete(root);
    return ESP_OK;
}

static cJSON *load_saved_wlan_file() {
    FILE *f = fopen(SAVED_WLAN_FILEPATH, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = malloc(filesize + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    fread(buffer, 1, filesize, f);
    buffer[filesize] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(buffer);
    free(buffer);
    return json;
}

static esp_err_t update_saved_wlan_file() {
    FILE *f = fopen("/spiffs/saved_wlan.json", "w");
    if (!f) {
        ESP_LOGE(TAG_WEB, "Failed to open file for writing");
        return ESP_FAIL;
    }

    char *json_str = cJSON_PrintUnformatted(saved_wlan);
    if (!json_str) {
        ESP_LOGE(TAG_WEB, "Failed to create JSON string");
        fclose(f);
        return ESP_FAIL;
    }
    ESP_LOGE(TAG_WEB, "current json: %s", json_str);

    size_t written = fwrite(json_str, 1, strlen(json_str), f);
    if (written != strlen(json_str)) {
        ESP_LOGE(TAG_WEB, "Failed to write complete JSON to file");
        free(json_str);
        fclose(f);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG_WEB, "WLAN config saved (%d bytes)", written);

    free(json_str);
    fclose(f);
    return ESP_OK;
}

static esp_err_t remove_ssid_from_saved_wlan(const char *ssid) {
    if (!saved_wlan)
        return ESP_FAIL;
    cJSON_DeleteItemFromObject(saved_wlan, ssid);
    update_saved_wlan_file();
    return ESP_OK;
}

static esp_err_t add_ssid_to_saved_wlan(const char *ssid, cJSON *passwd) {
    if (!saved_wlan)
        return ESP_FAIL;
    cJSON_AddItemToObject(saved_wlan, ssid, passwd);
    update_saved_wlan_file();
    return ESP_OK;
}

static esp_err_t disconnectFromWLAN(const char *ssid) {
    if (strcmp(connected_ssid, ssid)) {
        ESP_LOGE(TAG_WEB, "diff req: %s, cur: %s.", ssid, connected_ssid);
        return ESP_FAIL;
    }
    if (esp_wifi_disconnect() != ESP_OK) {
        ESP_LOGE(TAG_WEB, "disconnect from ap failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t connect_to_nearby_wlan(const char *ssid, const char *passwd) {
    if (strlen(connected_ssid)) {
        disconnectFromWLAN(connected_ssid);
    }
    static wifi_config_t wifi_sta_config = {
        .sta = {
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .failure_retry_cnt = 5,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };
    strncpy((char *)wifi_sta_config.sta.ssid, ssid, sizeof(wifi_sta_config.sta.ssid) - 1);
    if (!strlen(passwd)) {
        wifi_sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    } else {
        wifi_sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        strncpy((char *)wifi_sta_config.sta.password, passwd, sizeof(wifi_sta_config.sta.password) - 1);
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config));
    esp_wifi_connect();
    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(5000));
    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGE(TAG_STA, "connect to %s fail", ssid);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t connect_to_saved_wlan(const char *ssid) {
    if (!saved_wlan) {
        ESP_LOGE(TAG_WEB, "saved_wlan has not been initialized!");
        return ESP_FAIL;
    }
    cJSON *passwd = cJSON_GetObjectItem(saved_wlan, ssid);
    if (!passwd || !cJSON_IsString(passwd)) {
        ESP_LOGE(TAG_WEB, "can not find passwd!");
        return ESP_FAIL;
    }
    return connect_to_nearby_wlan(ssid, passwd->valuestring);
}

static esp_err_t connect_to_nearby_saved_wlan() {
    static wifi_ap_record_t ap_records[MAX_SCAN_AP_NUMBER];
    uint16_t total_ap_num = MAX_SCAN_AP_NUMBER;
    if (fast_scan(&total_ap_num, ap_records) != ESP_OK) {
        return ESP_FAIL;
    }
    int max_rssi_idx = total_ap_num;
    for (int i = 0; i < total_ap_num; ++i) {
        wifi_ap_record_t *ap_record = &ap_records[i];
        if (!cJSON_GetObjectItem(saved_wlan, (char *) ap_record->ssid)) continue;
        if (max_rssi_idx == total_ap_num) {
            max_rssi_idx = i;
            continue;
        }
        if (ap_record->rssi > ap_records[max_rssi_idx].rssi) max_rssi_idx = i;
    }
    if (max_rssi_idx != total_ap_num) {
        connect_to_saved_wlan((char *) ap_records[max_rssi_idx].ssid);
    }
    return ESP_OK;
}

static esp_err_t root_get_handler(httpd_req_t *req) {
    const char* filepath = "/spiffs/static/index.html";
    httpd_send_file_with_chunk(req, filepath);
    return ESP_OK;
}

static esp_err_t wlan_post_handler(httpd_req_t* req) {
    esp_err_t ret = ESP_OK;
    // recv post
    static char buf[1024] = {0};
    if (httpd_req_recv(req, buf, sizeof(buf) - 1) <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "未接收任何数据");
        return ESP_FAIL;
    }

    // parse JSON
    cJSON *root, *group, *action, *ssid, *passwd;
    root = group = action = ssid = passwd = NULL;
    root = cJSON_Parse(buf);
    group = cJSON_GetObjectItem(root, "group");
    action = cJSON_GetObjectItem(root, "action");
    ssid = cJSON_GetObjectItem(root, "ssid");
    passwd = cJSON_GetObjectItem(root, "passwd");

    // handle
    if (!group || !cJSON_IsString(group)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "无法从json解析group");
        ret = ESP_FAIL;
        goto wlan_over;
    }
    if (!ssid || !cJSON_IsString(ssid)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "无法从json解析ssid");
        ret = ESP_FAIL;
        goto wlan_over;
    }
    if (action && cJSON_IsString(action)) {
        // saved wlan
        if (strcmp(action->valuestring, "forget") == 0) {
            ret = remove_ssid_from_saved_wlan(ssid->valuestring);
        } else if (strcmp(action->valuestring, "connect") == 0) {
            ret = connect_to_saved_wlan(ssid->valuestring);
        } else
            ret = ESP_FAIL;
        goto wlan_over;
    } else if (passwd && cJSON_IsString(passwd)) {
        // nearby wlan
        ret = connect_to_nearby_wlan(ssid->valuestring, passwd->valuestring);
        if (ret == ESP_OK && strlen(passwd->valuestring))
            add_ssid_to_saved_wlan(ssid->valuestring, passwd);
        goto wlan_over;
    } else {
        // connected wlan
        ret = disconnectFromWLAN(ssid->valuestring);
        goto wlan_over;
    }
    
wlan_over:
    cJSON_Delete(root);
    if (ret == ESP_OK)
        httpd_resp_sendstr(req, "操作成功");
    else
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "操作失败");
    return ret;
}

static esp_err_t wol_post_handler(httpd_req_t* req) {
    // 读取POST数据
    char buf[1024] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "未接收到任何数据");
        return ESP_FAIL;
    }

    // 解析JSON，获取mac_address字段
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "无法从json解析group");
        return ESP_FAIL;
    }
    cJSON *mac_item = cJSON_GetObjectItem(root, "mac_address");
    if (!mac_item || !cJSON_IsString(mac_item)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "无法从json解析mac_address");
        return ESP_FAIL;
    }

    // 调用发送魔术包函数
    send_magic_packet(mac_item->valuestring);

    static char text[128];
    sprintf(text, "已发送魔术包至[%s]", mac_item->valuestring);
    cJSON_Delete(root);
    httpd_resp_sendstr(req, text);
    return ESP_OK;
}

static esp_err_t upload_post_handler(httpd_req_t* req) {
    if (req->content_len > (1024 * 1536)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "固件大小不得大于1.5MB");
        return ESP_FAIL;
    }

    char buf[1024];
    int received;
    FILE *f = fopen("/spiffs/bin/fireware.bin", "w");
    if (!f) {
        ESP_LOGE(TAG_WEB, "打开文件失败");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "固件上传失败");
        return ESP_FAIL;
    }

    while ((received = httpd_req_recv(req, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, received, f);
    }

    fclose(f);
    httpd_resp_sendstr(req, "固件上传成功");
    return ESP_OK;
}

void restart_task(void* pvParameters) {
    vTaskDelay(pdMS_TO_TICKS(3000));  // 延迟3秒
    esp_restart();
}

static esp_err_t upgrade_get_handler(httpd_req_t* req) {
    FILE *f = fopen("/spiffs/bin/fireware.bin", "rb");
    if (!f) {
        ESP_LOGE(TAG_OTA, "Failed to open firmware file");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "还未上传固件");
        return ESP_FAIL;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition) {
        ESP_LOGE(TAG_OTA, "No OTA partition found");
        fclose(f);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
        return ESP_FAIL;
    }

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_OTA, "esp_ota_begin failed");
        fclose(f);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
        return err;
    }

    uint8_t *buf = malloc(OTA_BUF_SIZE);
    if (!buf) {
        ESP_LOGE(TAG_OTA, "Failed to allocate buffer");
        fclose(f);
        esp_ota_end(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
        return ESP_ERR_NO_MEM;
    }

    size_t read_bytes;
    while ((read_bytes = fread(buf, 1, OTA_BUF_SIZE, f)) > 0) {
        err = esp_ota_write(ota_handle, buf, read_bytes);
        if (err != ESP_OK) {
            ESP_LOGE(TAG_OTA, "esp_ota_write failed: %s", esp_err_to_name(err));
            free(buf);
            fclose(f);
            esp_ota_end(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
            return err;
        }
    }

    free(buf);
    fclose(f);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_OTA, "esp_ota_end failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
        return err;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_OTA, "esp_ota_set_boot_partition failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "升级失败");
        return err;
    }

    httpd_resp_sendstr(req, "升级成功, 设备将在3秒后重启");
    ESP_LOGI(TAG_OTA, "OTA update written successfully. Restarting...");
    xTaskCreate(restart_task, "restart_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

static esp_err_t static_file_get_handler(httpd_req_t* req) {
    // get filepath
    char filepath[1024] = "/spiffs/static";
    strncat(filepath, req->uri, sizeof(filepath) - strlen(filepath) - 1);

    // set Content-Type according to the file extension type
    const char* ext = strrchr(filepath, '.');
    if (ext) {
        if (strcmp(ext, ".html") == 0)
            httpd_resp_set_type(req, "text/html");
        else if (strcmp(ext, ".css") == 0)
            httpd_resp_set_type(req, "text/css");
        else if (strcmp(ext, ".js") == 0)
            httpd_resp_set_type(req, "application/javascript");
        else if (strcmp(ext, ".webp") == 0)
            httpd_resp_set_type(req, "image/webp");
        else if (strcmp(ext, ".ico") == 0)
            httpd_resp_set_type(req, "image/x-icon");
        else if (strcmp(ext, ".png") == 0)
            httpd_resp_set_type(req, "image/png");
        // add other type later
    }

    return httpd_send_file_with_chunk(req, filepath);
}

static httpd_handle_t web_server_start(void) {
    saved_wlan = load_saved_wlan_file();
    if (saved_wlan) {
        connect_to_nearby_saved_wlan();
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 16;
    config.lru_purge_enable = true;
    config.server_port = 80;
    config.stack_size = 4096;
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t root_get_uri = {
            .uri       = "/",
            .method    = HTTP_GET,
            .handler   = root_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &root_get_uri);

        httpd_uri_t status_uri = {
            .uri = "/status",
            .method = HTTP_GET,
            .handler = status_get_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &status_uri);

        httpd_uri_t scan_uri = {
            .uri = "/scan",
            .method = HTTP_GET,
            .handler = scan_get_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &scan_uri);

        httpd_uri_t wlan_uri = {
            .uri = "/wlan",
            .method = HTTP_POST,
            .handler = wlan_post_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &wlan_uri);

        httpd_uri_t wol_uri = {
            .uri = "/wol",
            .method = HTTP_POST,
            .handler = wol_post_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &wol_uri);

        httpd_uri_t upload_uri = {
            .uri = "/upload",
            .method = HTTP_POST,
            .handler = upload_post_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &upload_uri);

        httpd_uri_t upgrade_uri = {
            .uri = "/upgrade",
            .method = HTTP_GET,
            .handler = upgrade_get_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &upgrade_uri);

        httpd_uri_t static_uri = {
            .method = HTTP_GET,
            .handler = static_file_get_handler,
            .user_ctx = NULL,
        };
        static_uri.uri = "/index.html";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/style.css";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/script.js";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/background.webp";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/favicon.ico";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/rssi_sprites.png";
        httpd_register_uri_handler(server, &static_uri);
        static_uri.uri = "/lock_sprites.png";
        httpd_register_uri_handler(server, &static_uri);
    }
    return server;
}

esp_err_t esp_wol_init() {
    esp_err_t ret;

    // Initialize SPIFFS
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };
    ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE("SPIFFS", "Failed to mount SPIFFS");
    } else {
        ESP_LOGI("SPIFFS", "SPIFFS mounted");
    }

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    wifi_init();
    create_udp_socket();
    web_server_start();
    
    return ESP_OK;
}
