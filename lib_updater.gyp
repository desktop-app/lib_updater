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
    ],
    'variables': {
      'src_loc': '.',
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
    ],
    'direct_dependent_settings': {
      'include_dirs': [
        '<(src_loc)',
      ],
    },
    'sources': [
      '<(src_loc)/updater/updater_checker.cpp',
      '<(src_loc)/updater/updater_checker.h',
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
        'zlibstat',
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
      '<(libs_loc)/zlib',
      '<(private_loc)/<(private_name)',
      '<(public_key_loc)',
    ],
    'sources': [
      '<(src_loc)/updater/update_packer.cpp',
    ],
    'configurations': {
      'Debug': {
        'conditions': [[ 'build_win', {
          'library_dirs': [
            '<(libs_loc)/lzma/C/Util/LzmaLib/Debug',
            '<(libs_loc)/zlib/contrib/vstudio/vc14/x86/ZlibStatDebug',
          ],
        }]],
      },
      'Release': {
        'conditions': [[ 'build_win', {
          'library_dirs': [
            '<(libs_loc)/lzma/C/Util/LzmaLib/Release',
            '<(libs_loc)/zlib/contrib/vstudio/vc14/x86/ZlibStatReleaseWithoutAsm',
          ],
        }]],
      },
    },
  }],
}
