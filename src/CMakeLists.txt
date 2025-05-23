#*******************************************************************************
#  Copyright (c) 2015, 2024 logi.cals GmbH, Frank Pagliughi <fpagliughi@mindspring.com> and others
#
#  All rights reserved. This program and the accompanying materials
#  are made available under the terms of the Eclipse Public License v2.0
#  and Eclipse Distribution License v1.0 which accompany this distribution.
#
#  The Eclipse Public License is available at
#     https://www.eclipse.org/legal/epl-2.0/
#  and the Eclipse Distribution License is available at
#    http://www.eclipse.org/org/documents/edl-v10.php.
#
#  Contributors:
#     Rainer Poisel - initial version
#     Ian Craggs (IBM Corp.) - merge master
#     Ian Craggs - update for MQTTV5 support
#*******************************************************************************/

## compilation/linkage settings

configure_file(VersionInfo.h.in
  ${CMAKE_BINARY_DIR}/VersionInfo.h
  @ONLY
)

set(common_src
  MQTTTime.c
  MQTTProtocolClient.c
  Clients.c
  utf-8.c
  MQTTPacket.c
  MQTTPacketOut.c
  Messages.c
  Tree.c
  Socket.c
  Log.c
  MQTTPersistence.c
  Thread.c
  MQTTProtocolOut.c
  MQTTPersistenceDefault.c
  SocketBuffer.c
  LinkedList.c
  MQTTProperties.c
  MQTTReasonCodes.c
  Base64.c
  SHA1.c
  WebSocket.c
  Proxy.c
)

if(NOT PAHO_HIGH_PERFORMANCE)
  set(common_src ${common_src}
    StackTrace.c
    Heap.c
  )
endif()

if(WIN32)
  if(PAHO_WITH_LIBRESSL)
    set(LIBS_SYSTEM ws2_32 crypt32 rpcrt4 bcrypt)
  else()
    set(LIBS_SYSTEM ws2_32 crypt32 rpcrt4)
  endif()
elseif(UNIX)
  if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(LIBS_SYSTEM c dl pthread rt)
    # anl is only available with glibc so check if it is found before using
    # it or build will fail on uclibc or musl
    find_library(LIB_ANL anl)
    if(LIB_ANL)
      set(LIBS_SYSTEM "${LIBS_SYSTEM}" anl)
    endif()
    if(PAHO_WITH_LIBUUID)
      set(LIBS_SYSTEM "${LIBS_SYSTEM}" uuid)
    endif()
    add_definitions(-D_GNU_SOURCE -fvisibility=hidden)
  elseif(CMAKE_SYSTEM_NAME MATCHES "Android")
    set(LIBS_SYSTEM c dl)
  elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    set(LIBS_SYSTEM compat pthread)
  elseif(CMAKE_SYSTEM_NAME MATCHES "QNX")
    set(LIBS_SYSTEM c)
  else()
    set(LIBS_SYSTEM c pthread)
  endif()
endif()


install(
  FILES
    MQTTClient.h
    MQTTClientPersistence.h
    MQTTProperties.h
    MQTTReasonCodes.h
    MQTTSubscribeOpts.h
    MQTTExportDeclarations.h
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}
)

if (PAHO_WITH_ASL)

    # Prefer config-based find_package for better handling
    set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)

    # First look for the environment variable KRITIS3M_ASL_ROOT to prioritize a specific installation
    if(DEFINED ENV{KRITIS3M_ASL_ROOT})
        set(kritis3m_asl_DIR "$ENV{KRITIS3M_ASL_ROOT}/lib/cmake/kritis3m_asl")
        message(STATUS "Looking for kritis3m_asl in specified directory: ${kritis3m_asl_DIR}")
    endif()
    
    # Try to find the kritis3m_asl package
    find_package(kritis3m_asl QUIET)
    
    if(kritis3m_asl_FOUND)
        message(STATUS "Found kritis3m_asl: ${kritis3m_asl_DIR}")
        set(SSL_LIBRARY_NAME kritis3m_asl)
        set(SSL_INCLUDE_DIR ${kritis3m_asl_INCLUDE_DIR})
        set(SSL_ROOT_DIR ${kritis3m_asl_ROOT_DIR})
    else()
        # If not found, fetch and build it inline
        message(STATUS "kritis3m_asl not found, building it from source")
        
        # Add FetchContent module if not already included
        include(FetchContent)
        
        # Fetch kritis3m_asl from GitHub
        FetchContent_Declare(kritis3m_asl
            GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl.git
            GIT_TAG                 origin/main
            GIT_PROGRESS            TRUE
        )
        
        # Configure kritis3m_asl build options
        # Use STANDALONE=OFF to avoid installing into system directories
        set(KRITIS3M_ASL_STANDALONE OFF CACHE BOOL "Build kritis3m_asl as standalone" FORCE)
        set(KRITIS3M_ASL_ENABLE_PKCS11 ON CACHE BOOL "Enable PKCS11 support" FORCE)
        set(KRITIS3M_ASL_PKCS11_CRYPTO OFF CACHE BOOL "Use PKCS11 for crypto" FORCE)
        
        # Add the asl subproject
        FetchContent_GetProperties(kritis3m_asl)
        if(NOT kritis3m_asl_POPULATED)
            FetchContent_Populate(kritis3m_asl)
            add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR} EXCLUDE_FROM_ALL)
        endif()
        
        # Set paths for the inline-built version
        set(SSL_LIBRARY_NAME kritis3m_asl)
        set(SSL_INCLUDE_DIR ${kritis3m_asl_SOURCE_DIR}/include)
        set(SSL_ROOT_DIR ${kritis3m_asl_SOURCE_DIR})
    endif()

    # Add explicit link directories to avoid runtime search path issues
    if(kritis3m_asl_FOUND)
        link_directories(${kritis3m_asl_DIR}/../..)
    else()
        link_directories(${kritis3m_asl_BINARY_DIR})
    endif()

    add_library(kritis3m_mqtt STATIC
                        ${common_src}
                        MQTTClient.c
                        ASLSocket.c
    )
    target_include_directories(kritis3m_mqtt PUBLIC
      PUBLIC
        ${SSL_INCLUDE_DIR}
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      PRIVATE
        ${CMAKE_BINARY_DIR})
  

    set_target_properties(kritis3m_mqtt PROPERTIES
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      COMPILE_DEFINITIONS "PAHO_ASL=1;PAHO_MQTT_STATIC=1"
    )

    target_compile_definitions(kritis3m_mqtt  PRIVATE PAHO_ASL=1;PAHO_MQTT_STATIC=1)

    # Use a consistent naming scheme for linking
    if(TARGET kritis3m_asl)
        target_link_libraries(kritis3m_mqtt PUBLIC kritis3m_asl ${LIBS_SYSTEM})
    else()
        message(FATAL_ERROR "kritis3m_asl target not found")
    endif()


    add_library(kritis3m_mqtt_as STATIC
                        ${common_src}
                        MQTTAsync.c
                        MQTTAsyncUtils.c
                        ASLSocket.c
    )
    target_include_directories(kritis3m_mqtt_as PUBLIC
      PUBLIC
        ${SSL_INCLUDE_DIR}
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      PRIVATE
        ${CMAKE_BINARY_DIR})
  

    set_target_properties(kritis3m_mqtt_as PROPERTIES
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      COMPILE_DEFINITIONS "PAHO_ASL=1;PAHO_MQTT_STATIC=1"
    )

    target_compile_definitions(kritis3m_mqtt_as  PRIVATE PAHO_ASL=1;PAHO_MQTT_STATIC=1)

    # Use a consistent naming scheme for linking
    if(TARGET kritis3m_asl)
        target_link_libraries(kritis3m_mqtt_as PUBLIC kritis3m_asl ${LIBS_SYSTEM})
    else()
        message(FATAL_ERROR "kritis3m_asl target not found")
    endif()



else ()

if(PAHO_BUILD_SHARED)
  # common compilation for libpaho-mqtt3c and libpaho-mqtt3a
  add_library(common_obj OBJECT ${common_src})
  set_target_properties(common_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_definitions(common_obj PRIVATE PAHO_MQTT_EXPORTS=1)

  add_executable(MQTTVersion MQTTVersion.c)
  target_compile_definitions(MQTTVersion PUBLIC PAHO_MQTT_IMPORTS=1)
endif()

if(PAHO_BUILD_STATIC)
  add_library(common_obj_static OBJECT ${common_src})
  set_target_properties(common_obj_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_definitions(common_obj_static PRIVATE PAHO_MQTT_STATIC=1)
endif()

if(PAHO_BUILD_SHARED)
  add_library(paho-mqtt3c SHARED
    $<TARGET_OBJECTS:common_obj>
    MQTTClient.c
  )
  add_library(paho-mqtt3a SHARED
    $<TARGET_OBJECTS:common_obj>
    MQTTAsync.c
    MQTTAsyncUtils.c
  )

  add_library(eclipse-paho-mqtt-c::paho-mqtt3c ALIAS paho-mqtt3c)
  add_library(eclipse-paho-mqtt-c::paho-mqtt3a ALIAS paho-mqtt3a)
    
  target_link_libraries(paho-mqtt3c ${LIBS_SYSTEM})
  target_link_libraries(paho-mqtt3a ${LIBS_SYSTEM})
  target_link_libraries(MQTTVersion paho-mqtt3a paho-mqtt3c ${LIBS_SYSTEM})
    
  set_target_properties(paho-mqtt3c paho-mqtt3a PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    COMPILE_DEFINITIONS "PAHO_MQTT_EXPORTS=1"
  )

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    set(MQTTCLIENT_ENTRY_POINT _MQTTClient_init)
    set(MQTTASYNC_ENTRY_POINT _MQTTAsync_init)
  elseif(NOT WIN32)
    set(MQTTCLIENT_ENTRY_POINT MQTTClient_init)
    set(MQTTASYNC_ENTRY_POINT MQTTAsync_init)
  endif()

  if(NOT WIN32)
    set_target_properties(paho-mqtt3c PROPERTIES
      LINK_FLAGS "-Wl,-init,${MQTTCLIENT_ENTRY_POINT}"
    )
    set_target_properties(paho-mqtt3a PROPERTIES
      LINK_FLAGS "-Wl,-init,${MQTTASYNC_ENTRY_POINT}"
    )
  endif()

  foreach(TARGET paho-mqtt3c paho-mqtt3a)
    target_include_directories(${TARGET}
      PUBLIC
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      PRIVATE
        ${CMAKE_BINARY_DIR})
  endforeach()

  install(TARGETS paho-mqtt3c paho-mqtt3a
    EXPORT eclipse-paho-mqtt-cTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )

  install(TARGETS MQTTVersion
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
endif()

if(PAHO_BUILD_STATIC)
  add_library(paho-mqtt3c-static STATIC
    $<TARGET_OBJECTS:common_obj_static>
    MQTTClient.c
  )
  add_library(paho-mqtt3a-static STATIC
    $<TARGET_OBJECTS:common_obj_static>
    MQTTAsync.c
    MQTTAsyncUtils.c
  )

  add_library(eclipse-paho-mqtt-c::paho-mqtt3c-static ALIAS paho-mqtt3c-static)
  add_library(eclipse-paho-mqtt-c::paho-mqtt3a-static ALIAS paho-mqtt3a-static)

  target_link_libraries(paho-mqtt3c-static ${LIBS_SYSTEM})
  target_link_libraries(paho-mqtt3a-static ${LIBS_SYSTEM})

  if(NOT WIN32)
    set_target_properties(paho-mqtt3c-static PROPERTIES OUTPUT_NAME paho-mqtt3c)
    set_target_properties(paho-mqtt3a-static PROPERTIES OUTPUT_NAME paho-mqtt3a)
  endif()       

  set_target_properties(paho-mqtt3c-static paho-mqtt3a-static PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    COMPILE_DEFINITIONS "PAHO_MQTT_STATIC=1"
  )

  foreach(TARGET paho-mqtt3c-static paho-mqtt3a-static)
    target_include_directories(${TARGET}
      PUBLIC
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      PRIVATE
        ${CMAKE_BINARY_DIR})
  endforeach()

  if(NOT PAHO_BUILD_SHARED)
    install(TARGETS paho-mqtt3c-static paho-mqtt3a-static
      EXPORT eclipse-paho-mqtt-cTargets
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  else()
    install(TARGETS paho-mqtt3c-static paho-mqtt3a-static
      EXPORT eclipse-paho-mqtt-cTargets
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
  endif()
endif()

if(PAHO_WITH_SSL OR PAHO_WITH_LIBRESSL)
  if(PAHO_WITH_LIBRESSL)
    find_package(LibreSSL REQUIRED)
    set(SSL_LIBRARY_NAME LibreSSL)
    set(SSL_INCLUDE_DIR ${LIBRESSL_INCLUDE_DIR})
    set(SSL_ROOT_DIR ${LIBRESSL_ROOT_DIR})
  else()
    find_package(OpenSSL REQUIRED)
    set(SSL_LIBRARY_NAME OpenSSL)
    set(SSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(SSL_ROOT_DIR ${OPENSSL_ROOT_DIR})
  endif()
  message(STATUS "Using ${SSL_LIBRARY_NAME} with headers at ${SSL_INCLUDE_DIR}")

  if(PAHO_BUILD_SHARED)
    ## common compilation for libpaho-mqtt3cs and libpaho-mqtt3as
    ## Note: SSL libraries must be recompiled due to ifdefs
    add_library(common_ssl_obj OBJECT ${common_src})
    target_include_directories(common_ssl_obj PUBLIC ${SSL_INCLUDE_DIR})

    set_property(TARGET common_ssl_obj PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(common_ssl_obj PRIVATE OPENSSL=1 PAHO_MQTT_EXPORTS=1)
    
    add_library(paho-mqtt3cs SHARED
      $<TARGET_OBJECTS:common_ssl_obj>
      MQTTClient.c
      SSLSocket.c
    )
    add_library(paho-mqtt3as SHARED
      $<TARGET_OBJECTS:common_ssl_obj>
      MQTTAsync.c
      MQTTAsyncUtils.c
      SSLSocket.c
    )

    add_library(eclipse-paho-mqtt-c::paho-mqtt3cs ALIAS paho-mqtt3cs)
    add_library(eclipse-paho-mqtt-c::paho-mqtt3as ALIAS paho-mqtt3as)

    set_target_properties(paho-mqtt3cs paho-mqtt3as PROPERTIES
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      COMPILE_DEFINITIONS "OPENSSL=1;PAHO_MQTT_EXPORTS=1"
    )

    if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
      set(MQTTCLIENT_ENTRY_POINT _MQTTClient_init)
      set(MQTTASYNC_ENTRY_POINT _MQTTAsync_init)
    elseif(NOT WIN32)
      set(MQTTCLIENT_ENTRY_POINT MQTTClient_init)
      set(MQTTASYNC_ENTRY_POINT MQTTAsync_init)
    endif()

    if(NOT WIN32)
      set_target_properties(paho-mqtt3cs PROPERTIES
        LINK_FLAGS "-Wl,-init,${MQTTCLIENT_ENTRY_POINT}"
      )
      set_target_properties(paho-mqtt3as PROPERTIES
        LINK_FLAGS "-Wl,-init,${MQTTASYNC_ENTRY_POINT}")
    endif()

    foreach(TARGET paho-mqtt3cs paho-mqtt3as)
      target_include_directories(${TARGET}
        PUBLIC
          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        PRIVATE
          ${CMAKE_BINARY_DIR}
      )
      target_link_libraries(${TARGET}
        PUBLIC
          ${SSL_LIBRARY_NAME}::SSL ${SSL_LIBRARY_NAME}::Crypto ${LIBS_SYSTEM}
      )
    endforeach()

    install(TARGETS paho-mqtt3cs paho-mqtt3as
      EXPORT eclipse-paho-mqtt-cTargets
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()

  if(PAHO_BUILD_STATIC)
    ## common compilation for libpaho-mqtt3cs and libpaho-mqtt3as
    ## Note: SSL libraries must be recompiled due ifdefs
    add_library(common_ssl_obj_static OBJECT ${common_src})
    target_include_directories(common_ssl_obj_static PUBLIC ${SSL_INCLUDE_DIR})

    set_property(TARGET common_ssl_obj_static PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(common_ssl_obj_static PRIVATE OPENSSL=1 PAHO_MQTT_STATIC=1)
    
    add_library(paho-mqtt3cs-static STATIC
      $<TARGET_OBJECTS:common_ssl_obj_static>
      MQTTClient.c
      SSLSocket.c
    )
    add_library(paho-mqtt3as-static STATIC
      $<TARGET_OBJECTS:common_ssl_obj_static>
      MQTTAsync.c
      MQTTAsyncUtils.c
      SSLSocket.c
    )

    add_library(eclipse-paho-mqtt-c::paho-mqtt3cs-static ALIAS paho-mqtt3cs-static)
    add_library(eclipse-paho-mqtt-c::paho-mqtt3as-static ALIAS paho-mqtt3as-static)

    set_target_properties(paho-mqtt3cs-static paho-mqtt3as-static PROPERTIES
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      COMPILE_DEFINITIONS "OPENSSL=1;PAHO_MQTT_STATIC=1"
    )

    if(NOT WIN32)
      set_target_properties(paho-mqtt3cs-static PROPERTIES OUTPUT_NAME paho-mqtt3cs)
      set_target_properties(paho-mqtt3as-static PROPERTIES OUTPUT_NAME paho-mqtt3as)
    endif()

    if(NOT WIN32)
      set_target_properties(paho-mqtt3cs-static PROPERTIES
        LINK_FLAGS "-Wl,-init,${MQTTCLIENT_ENTRY_POINT}"
      )
      set_target_properties(paho-mqtt3as-static PROPERTIES
        LINK_FLAGS "-Wl,-init,${MQTTASYNC_ENTRY_POINT}"
      )
    endif()

    if(NOT PAHO_BUILD_SHARED)
      install(TARGETS paho-mqtt3cs-static paho-mqtt3as-static
        EXPORT eclipse-paho-mqtt-cTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      )
    else()
      install(TARGETS paho-mqtt3cs-static paho-mqtt3as-static
        EXPORT eclipse-paho-mqtt-cTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      )
    endif()

    foreach(TARGET paho-mqtt3cs-static paho-mqtt3as-static)
      target_include_directories(${TARGET}
        PUBLIC
          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        PRIVATE
          ${CMAKE_BINARY_DIR}
      )
      target_link_libraries(${TARGET}
        PUBLIC
          ${SSL_LIBRARY_NAME}::SSL ${SSL_LIBRARY_NAME}::Crypto ${LIBS_SYSTEM}
      )
    endforeach()
  endif()
endif()

install(EXPORT eclipse-paho-mqtt-cTargets
  FILE eclipse-paho-mqtt-cConfig.cmake
  NAMESPACE eclipse-paho-mqtt-c::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eclipse-paho-mqtt-c
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file("eclipse-paho-mqtt-cConfigVersion.cmake"
  VERSION ${CLIENT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/eclipse-paho-mqtt-cConfigVersion.cmake"
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/eclipse-paho-mqtt-c
)

# Base64 test
add_executable(Base64Test EXCLUDE_FROM_ALL Base64.c Base64.h)
target_compile_definitions(Base64Test PUBLIC BASE64_TEST)

if(PAHO_WITH_SSL OR PAHO_WITH_LIBRESSL)
  add_executable(Base64TestOpenSSL EXCLUDE_FROM_ALL Base64.c Base64.h )
  target_link_libraries(Base64TestOpenSSL ${SSL_LIBRARY_NAME}::SSL ${SSL_LIBRARY_NAME}::Crypto)
  target_compile_definitions(Base64TestOpenSSL PUBLIC BASE64_TEST OPENSSL=1)
endif()

# SHA1 test
add_executable(Sha1Test EXCLUDE_FROM_ALL SHA1.c SHA1.h)
target_compile_definitions(Sha1Test PUBLIC SHA1_TEST)

if(PAHO_WITH_SSL OR PAHO_WITH_LIBRESSL)
	add_executable(Sha1TestOpenSSL EXCLUDE_FROM_ALL SHA1.c SHA1.h)
	target_link_libraries(Sha1TestOpenSSL ${SSL_LIBRARY_NAME}::SSL ${SSL_LIBRARY_NAME}::Crypto)
	target_compile_definitions(Sha1TestOpenSSL PUBLIC SHA1_TEST OPENSSL=1)
endif()


endif(PAHO_WITH_ASL)
