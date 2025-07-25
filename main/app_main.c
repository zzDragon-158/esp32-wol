#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wol.h"
#include "esp_blink.h"

void app_main(void)
{
    esp_wol_init();
    xTaskCreate(
        blink_main,
        "blink",
        2048,
        NULL,
        5,
        NULL
    );
}
