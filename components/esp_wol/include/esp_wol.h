#ifndef _ESP_WOL_H_
#define _ESP_WOL_H_

#include "sdkconfig.h"
// wifi relation
#include <string.h>
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif_net_stack.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#if IP_NAPT
#include "lwip/lwip_napt.h"
#endif
#include "lwip/err.h"
#include "lwip/sys.h"

// web relation
#include "esp_http_server.h"
#include "esp_spiffs.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"

// ota
#include "esp_ota_ops.h"
#include "esp_partition.h"

esp_err_t esp_wol_init();

#endif
