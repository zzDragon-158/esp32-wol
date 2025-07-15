idf_component_register(SRCS "")
spiffs_create_partition_image(spiffs ${CMAKE_CURRENT_SOURCE_DIR} FLASH_IN_PROJECT)
