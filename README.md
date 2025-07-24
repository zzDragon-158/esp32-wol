| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- |

# ESP32 WOL

使用你的手机WIFI连接到ESP32 AP，然后通过访问网关地址(通常是`192.168.4.1`)进入ESP32的控制后台。
连接WLAN后，就可以通过WOL功能向局域网中的设备发送魔术包了。
如果连接的WLAN可以分配公网IPv6地址，那么你还可以在任何地方通过访问设备的公网IPv6地址来进入ESP32的控制后台，通过WOL功能远程唤醒局域网设备。

## How to use
### Configure the project

Open the project configuration menu (`idf.py menuconfig`).

In the `ESP32 WOL Configuration` menu:

* Set the Wi-Fi SoftAP configuration.
    * Set `WiFi AP SSID`.
    * Set `WiFi AP Password`.

* Set the Wi-Fi STA configuration.
    * Set `WiFi scan method`.

* Set the BLINK configuration.
    * Select the LED type in the `Blink LED type` option.
        * Use `GPIO` for regular LED
        * Use `LED strip` for addressable LED
    * If the LED type is `LED strip`, select the backend peripheral
        * `RMT` is only available for ESP targets with RMT peripheral supported
        * `SPI` is available for all ESP targets
    * Set the GPIO number used for the signal in the `Blink GPIO number` option.
    * Set the blinking period in the `Blink period in ms` option.

Optional: If necessary, modify the other choices to suit your needs.

### Build and Flash

Build the project and flash it to the board, then run the monitor tool to view the serial output:

Run `idf.py -p PORT flash monitor` to build, flash and monitor the project.

(To exit the serial monitor, type ``Ctrl-]``.)
