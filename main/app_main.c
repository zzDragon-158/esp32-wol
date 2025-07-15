#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wol.h"

void app_main(void)
{
    esp_wol_init();
}
