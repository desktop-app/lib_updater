# This file is part of Desktop App Toolkit,
# a set of libraries for developing nice desktop applications.
#
# For license and copyright information please follow this link:
# https://github.com/desktop-app/legal/blob/master/LEGAL

{
  'includes': [
    '../gyp/helpers/common/common.gypi',
  ],
  'targets': [{
    'target_name': 'lib_updater',
    'includes': [
      '../gyp/helpers/common/library.gypi',
      '../gyp/helpers/modules/openssl.gypi',
      '../gyp/helpers/modules/qt.gypi',
      '../gyp/helpers/modules/pch.gypi',
    ],
    'variables': {
      'src_loc': '.',
      'public_key_loc%': '',
      'pch_source': '<(src_loc)/updater/details/updater_pch.cpp',
      'pch_header': '<(src_loc)/updater/details/updater_pch.h',
    },
    'defines': [
    ],
    'dependencies': [
      '<(submodules_loc)/lib_base/lib_base.gyp:lib_base',
    ],
    'export_dependent_settings': [
      '<(submodules_loc)/lib_base/lib_base.gyp:lib_base',
    ],
    'include_dirs': [
      '<(src_loc)',
      '<(public_key_loc)',
    ],
    'conditions': [[ 'build_win', {
      'include_dirs': [
        '<(libs_loc)/lzma/C',
      ],
    }, {
      'include_dirs': [
        '/usr/local/include',
      ],
      'library_dirs': [
        '/usr/local/lib',
      ],
    }]],
    'direct_dependent_settings': {
      'include_dirs': [
        '<(src_loc)',
      ],
      'configurations': {
        'Debug': {
          'conditions': [[ 'build_win', {
            'library_dirs': [
              '<(libs_loc)/lzma/C/Util/LzmaLib/Debug',
            ],
          }]],
        },
        'Release': {
          'conditions': [[ 'build_win', {
            'library_dirs': [
              '<(libs_loc)/lzma/C/Util/LzmaLib/Release',
            ],
          }]],
        },
      },
      'conditions': [[ 'build_win', {
        'libraries': [
          '-lLzmaLib',
        ],
      }, {
        'include_dirs': [
          '/usr/local/include',
        ],
        'library_dirs': [
          '/usr/local/lib',
        ],
      }], [ 'build_linux', {
        'libraries': [
          '-llzma',
        ],
      }], [ 'build_mac', {
        'xcode_settings': {
          'OTHER_LDFLAGS': [
            '-llzma',
          ],
        },
      }]],
    },
    'sources': [
      '<(src_loc)/updater/details/updater_checker.cpp',
      '<(src_loc)/updater/details/updater_checker.h',
      '<(src_loc)/updater/details/updater_http_checker.cpp',
      '<(src_loc)/updater/details/updater_http_checker.h',
      '<(src_loc)/updater/details/updater_http_loader.cpp',
      '<(src_loc)/updater/details/updater_http_loader.h',
      '<(src_loc)/updater/details/updater_install_methods.cpp',
      '<(src_loc)/updater/details/updater_install_methods.h',
      '<(src_loc)/updater/details/updater_loader.cpp',
      '<(src_loc)/updater/details/updater_loader.h',
      '<(src_loc)/updater/details/updater_unpack.cpp',
      '<(src_loc)/updater/details/updater_unpack.h',
      '<(src_loc)/updater/updater_instance.cpp',
      '<(src_loc)/updater/updater_instance.h',
    ],
  }, {
    'target_name': 'update_packer',
    'variables': {
      'src_loc': '.',
      'mac_target': '10.12',
      'private_name%': '',
      'public_key_loc%': '',
    },
    'includes': [
      '../gyp/helpers/common/executable.gypi',
      '../gyp/helpers/modules/qt.gypi',
      '../gyp/helpers/modules/openssl.gypi',
    ],
    'conditions': [[ 'build_win', {
      'libraries': [
        'LzmaLib',
      ],
    }, {
      'include_dirs': [
        '/usr/local/include',
      ],
      'library_dirs': [
        '/usr/local/lib',
      ],
    }], [ 'build_linux', {
      'libraries': [
        '<(linux_lib_ssl)',
        '<(linux_lib_crypto)',
        'lzma',
      ],
    }], [ 'build_mac', {
      'xcode_settings': {
        'OTHER_LDFLAGS': [
          '-llzma',
        ],
      },
    }]],
    'include_dirs': [
      '<(src_loc)',
      '<(libs_loc)/lzma/C',
      '<(private_loc)/<(private_name)',
      '<(public_key_loc)',
    ],
    'sources': [
      '<(src_loc)/updater/packer/updater_update_packer.cpp',
    ],
    'configurations': {
      'Debug': {
        'conditions': [[ 'build_win', {
          'library_dirs': [
            '<(libs_loc)/lzma/C/Util/LzmaLib/Debug',
          ],
        }]],
      },
      'Release': {
        'conditions': [[ 'build_win', {
          'library_dirs': [
            '<(libs_loc)/lzma/C/Util/LzmaLib/Release',
          ],
        }]],
      },
    },
  }, {
    'target_name': 'update_installer',
    'variables': {
      'src_loc': '.',
      'mac_target': '10.12',
      'private_name%': '',
      'public_key_loc%': '',
    },
    'includes': [
      '../gyp/helpers/common/executable.gypi',
    ],
    'sources': [
      '<(src_loc)/updater/installer/updater_update_installer.m',
    ],
  }],
}
