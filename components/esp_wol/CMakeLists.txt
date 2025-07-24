idf_component_register(SRCS "esp_wol.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_http_server spiffs esp_wifi lwip json esp_netif nvs_flash app_update esp_partition)
