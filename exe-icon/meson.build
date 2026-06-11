shared_module('exe-icon',
  ['exe_icon_plugin.vala'],
  dependencies: [dependency('gtk4'), libsingularity_dep, dependency('libpeas-2'), dependency('gdk-pixbuf-2.0')],
  install: true,
  install_dir: get_option('libdir') / 'singularity/plugins/exe-icon'
)

configure_file(
  input: 'exe-icon.plugin',
  output: 'exe-icon.plugin',
  copy: true,
  install: true,
  install_dir: get_option('libdir') / 'singularity/plugins/exe-icon'
)
