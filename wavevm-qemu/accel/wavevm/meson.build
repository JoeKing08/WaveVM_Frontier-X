wavevm_ss = ss.source_set()
wavevm_ss.add(files(
  'wavevm-all.c',
  'wavevm-cpu.c',
  'wavevm-tcg.c',
  'wavevm-user-mem.c',
  '../../hw/wavevm/wavevm-mem.c',
))

specific_ss.add_all(when: ['CONFIG_SOFTMMU', 'CONFIG_POSIX'], if_true: wavevm_ss)
