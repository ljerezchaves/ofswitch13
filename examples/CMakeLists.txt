build_lib_example(
  NAME ofswitch13-first
  SOURCE_FILES ofswitch13-first.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
)

build_lib_example(
  NAME ofswitch13-custom-switch
  SOURCE_FILES ofswitch13-custom-switch.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
)

build_lib_example(
  NAME ofswitch13-multiple-controllers
  SOURCE_FILES ofswitch13-multiple-controllers.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
)

build_lib_example(
  NAME ofswitch13-multiple-domains
  SOURCE_FILES ofswitch13-multiple-domains.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
)

build_lib_example(
  NAME ofswitch13-single-domain
  SOURCE_FILES ofswitch13-single-domain.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
)

build_lib_example(
  NAME ofswitch13-external-controller
  SOURCE_FILES ofswitch13-external-controller.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
    ${libtap-bridge}
)

build_lib_example(
  NAME ofswitch13-qos-controller
  SOURCE_FILES ofswitch13-qos-controller/main.cc
               ofswitch13-qos-controller/qos-controller.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libnetanim}
)

build_lib_example(
  NAME ofswitch13-logical-port
  SOURCE_FILES ofswitch13-logical-port/main.cc
               ofswitch13-logical-port/tunnel-controller.cc
               ofswitch13-logical-port/gtp-tunnel-app.cc
  LIBRARIES_TO_LINK
    ${libofswitch13}
    ${libinternet-apps}
    ${liblte}
)
