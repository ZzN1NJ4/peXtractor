# peXtractor

### Overview

Parses the PE file and displays information related to the metadata of the file like different headers and libraries imported. <br>
It prints different headers & their respective members (the important / interesting ones). There are 2 modes, Verbose & Non-Verbose <br>
- Non Verbose mode will print general headers & important members, and only the names of different sections.
- Verbose will print extra Data regarding the Headers & different sections.
<br>

You can read my blog on PE Structure [here](https://reze.gitbook.io/bin/winternal/pe-structure). <br>
I have explained the code written in my blog so you can check that out for any doubts. <br>
Or reach out to me on [Twitter](https://x.com/ZzN1NJ4).

### Example Output

```
D:\peXtractor\x64\Debug>peXtractor.exe

[*] Usage: run.exe /path/to/exe [options]

 Options:
-v, /v    Enable verbose mode for detailed output (mainly for section / import data part).
-h, /h    Prints this help information

 Description :
        Extracts and displays information from a PE file, which includes
        headers,section data, imports, and other metadata.
```

<br> <br> 
Non Verbose Mode
```
D:\peXtractor\x64\Debug>peXtractor.exe DLLInjex.exe

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=

[*] Magic Bytes: MZ
[*] File Size is 67072 bytes
[*] File Name: DLLInjex.exe
[*] MD5 hash : d41d8cd98f00b204e9800998ecf8427e
[*] 64-Bit PE File

##################      D O S   H E A D E R      ##################

[*] Magic Number                        @-- 0x5A4D
[*] NT Header Offset                    @-- 0xF8
[*] pe_base + 0x3C                      @-- 0xF8 (should be same as above)
[*] Relocation Table                    @-- 0x40

[+] Rich Header may be present

##################      R I C H   H E A D E R      ##################

[+] XOR Key: 0xE487B6E4

##################       N T   H E A D E R       ##################

[*] NT HEADER                           @-- 0xD09800F8
[*] Signature                           @-- 0x4550

##################     F I L E   H E A D E R     ##################

[*] FILE HEADER                         @-- 0xF8AFF660
[*] Machine                             @-- 0x8664
[*] No. of Sections                     @-- 10
[*] No. of Symbols                      @-- 0
[*] Pointer to Symbol Table             @-- 0x0
[*] Characteristics                     @-- 0x22
[*] Optional Header Size                @-- 0xF0

#################  O P T I O N A L   H E A D E R  #################

[*] OPTIONAL HEADER                     @-- 0xF8AFF6A0
[*] Magic                               @-- 0x20B
[*] MajorOSVersion                      @-- 0x6
[*] MinorOSVersion                      @-- 0x0
[*] .text Size                          @-- 0x8A00
[*] .text Offset                        @-- 0x1000
[*] Entry Point                         @-- 0x1129E
[*] Base of Code                        @-- 0x1000
[*] Image Base                          @-- 0x40000000
[*] Initialized Data Size               @-- 0x8000
[*] Uninitialized Data Size             @-- 0x0
[*] Image Base                          @-- 0x40000000
[*] Rva & Sizes                         @-- 0x16

#################         S E C T I O N S         #################
_______________________________________

[*] Section 1:  .textbss
[*] Section 2:  .text
[*] Section 3:  .rdata
[*] Section 4:  .data
[*] Section 5:  .pdata
[*] Section 6:  .idata
[*] Section 7:  .msvcjmc─☺
[*] Section 8:  .00cfg
[*] Section 9:  .rsrc
[*] Section 10:  .reloc
_______________________________________

#################         I M P O R T S           #################

[*] Data Directory                      @-- 0xF8AFEF00
[*] Export Table                        @-- 0x0 | Size: 0
[*] Import Table                        @-- 0x22408 | Size: 80
[*] IAT                                 @-- 0x22000 | Size: 1032
[*]  Libraries Used :

  KERNEL32.dll
  VCRUNTIME140D.dll
  ucrtbased.dll

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
```

### To Do

- Display functions being imported from a DLL
- Display information related to Relocations & stuff
- External Resources / Bound or Forwarded Imports.
- Allow Modifying the PE (like Remove Rich Headers, etc)
- Add some more functionality
- Maybe a Rust GUI to do all of this
