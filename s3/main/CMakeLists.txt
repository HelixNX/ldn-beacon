# s3proto.c / .h are shared with the desktop side (../../src)
idf_component_register(SRCS "main.c" "../../src/s3proto.c"
                       INCLUDE_DIRS "../../src"
                       PRIV_REQUIRES esp_wifi esp_event nvs_flash esp_driver_usb_serial_jtag esp_timer wpa_supplicant)
# LDN stations (main.c): no 4-way handshake from ESP-IDF's AP authenticator, the data key installed instead
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=wpa_auth_sta_associated" "-Wl,--wrap=hostap_new_assoc_sta")
