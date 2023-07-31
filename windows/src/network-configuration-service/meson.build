project('network-configuration-service', 'c')

if host_machine.system() == 'windows'
    add_project_arguments('-DUNICODE', language: 'c')
    add_project_arguments('-D_UNICODE', language: 'c')
endif

executable('network-configuration-service', 'network-configuration-service.c')