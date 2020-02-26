# This file is part of Desktop App Toolkit,
# a set of libraries for developing nice desktop applications.
#
# For license and copyright information please follow this link:
# https://github.com/desktop-app/legal/blob/master/LEGAL

add_library(lib_updater OBJECT)
add_library(desktop-app::lib_updater ALIAS lib_updater)
init_target(lib_updater)

get_filename_component(src_loc . REALPATH)

target_precompile_headers(lib_updater PRIVATE ${src_loc}/updater/details/updater_pch.h)
nice_target_sources(lib_updater ${src_loc}
PRIVATE
    updater/details/updater_checker.cpp
    updater/details/updater_checker.h
    updater/details/updater_http_checker.cpp
    updater/details/updater_http_checker.h
    updater/details/updater_http_loader.cpp
    updater/details/updater_http_loader.h
    updater/details/updater_install_methods.cpp
    updater/details/updater_install_methods.h
    updater/details/updater_loader.cpp
    updater/details/updater_loader.h
    updater/details/updater_unpack.cpp
    updater/details/updater_unpack.h
    updater/updater_instance.cpp
    updater/updater_instance.h
)

target_include_directories(lib_updater
PUBLIC
    ${src_loc}
PRIVATE
    ${submodules_loc}/${DESKTOP_APP_UPDATER_PUBLIC_KEY_LOC}
)

target_link_libraries(lib_updater
PUBLIC
    desktop-app::lib_base
    desktop-app::external_auto_updates
    desktop-app::external_qt
    desktop-app::external_openssl
)

add_executable(update_packer)
init_target(update_packer "(gen)")

set_target_properties(update_packer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${update_packer_output_folder})

nice_target_sources(update_packer ${src_loc}
PRIVATE
    updater/packer/updater_update_packer.cpp
)

target_include_directories(update_packer
PRIVATE
    ${submodules_loc}/${DESKTOP_APP_UPDATER_PUBLIC_KEY_LOC}
    ${submodules_loc}/../../DesktopPrivate/${DESKTOP_APP_UPDATER_PRIVATE_NAME}
)

target_link_libraries(update_packer
PUBLIC
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_auto_updates
    desktop-app::external_qt
    desktop-app::external_openssl
)
