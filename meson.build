project('gxlimg', 'c', default_options: ['buildtype=debugoptimized', 'c_std=gnu99'])

deps = [dependency('libssl'), dependency('libcrypto')]
srcs = ['amlcblk.c', 'amlsblk.c', 'bl2.c', 'bl3.c', 'fip.c', 'main.c']

add_project_arguments('-D_GNU_SOURCE', language: 'c')

if get_option('buildtype') == 'debug'
    add_project_arguments('-DDEBUG=1', language: 'c')
endif

executable('gxlimg', srcs, dependencies : deps)
