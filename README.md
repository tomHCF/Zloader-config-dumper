# Zloader_config_dumper
Tool for extracting Zloader config and unpacked binary from process based on: 
 - WinAppDbg https://github.com/MarioVilas/winappdbg
 - pefile https://github.com/erocarrera/pefile

Idea for this tool came from this analysis: https://johannesbader.ch/blog/the-dga-of-zloader/

The Zloder packer creates msiexec.exe process in suspended state, then injects an encrypted payload and a decryption stub to it, sets thread context to the stub and finally resumes execution. In next stage the stub decrypts payload and jumps to it. To extract config and unpacked PE pass PID of spawned msiexec.exe process as argument.

![alt text](https://github.com/tomHCF/Zloader_config_dumper/blob/master/usage.png?raw=true)
