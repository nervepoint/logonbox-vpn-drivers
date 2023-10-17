project('program', 'c')

lbv_dep = declare_dependency(
    link_args : ['-L../../../target', '-llbv'],
    include_directories : include_directories('../../../target'))

if host_machine.system() == 'windows'
    add_project_arguments('-DUNICODE', language: 'c')
    add_project_arguments('-D_UNICODE', language: 'c')
endif

executable('program', 'program.c', dependencies : lbv_dep)