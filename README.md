# peXtractor

### Overview

Parses the PE file and displays information related to the metadata of the file like different headers and libraries imported. <br>
It prints different headers & their respective members (the important / interesting ones). There are 2 modes, Verbose & Non-Verbose <br>
- Non Verbose mode will print general headers & important members, and only the names of different sections.
- Verbose will print extra Data regarding the Headers & different sections.
<br>

You can read my blog on PE Structure [here](https://reze.gitbook.io/bin/winternal/pe-structure). <br>
I have explained the code in my blog so you can check that out for any doubts. <br>
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
peXtractor.exe DLLInjex.exe -v

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=

[*] Magic Bytes: MZ
[*] File Size is 67072 bytes
[*] File Name: DLLInjex.exe
[*] MD5 hash : d41d8cd98f00b204e9800998ecf8427e
[*] 64-Bit PE File

##################      D O S   H E A D E R      ##################

[*] Magic Number                        @-- 0x5A4D
[*] NT Header Offset                    @-- 0xF8
[*] pe_start + 0x3C                     @-- 0xF8 (should be same as above)
[*] Relocation Table                    @-- 0x40

[*] Relocations         @-- 0x0
[*] Pages in File       @-- 0x3
[*] Checksum            @-- 0x0
[+] Rich Header may be present


##################      R I C H   H E A D E R      ##################

[+] XOR Key: 0xE487B6E4
[*] Rich Header Size : 96
[test] Comp ID  :  compid-hex  :  meaning  :  buildid  :  count  :  productid  :  version

[0] Comp ID: 0x0681010102000000  :  33030.257.2 : 33030   : 2      : Implib1400 :  Visual Studio 2015 14.00
[1] Comp ID: 0x0681050118000000  :  33030.261.24 : 33030   : 24     : Utc1900_CPP :  Visual Studio 2015 14.00
[2] Comp ID: 0x068104010B000000  :  33030.260.11 : 33030   : 11     : Utc1900_C :  Visual Studio 2015 14.00
[3] Comp ID: 0x0681030103000000  :  33030.259.3 : 33030   : 3      : Masm1400 :  Visual Studio 2015 14.00
[4] Comp ID: 0x4B78010105000000  :  30795.257.5 : 30795   : 5      : Implib1400 :  Visual Studio 2015 14.00
[5] Comp ID: 0x0000010052000000  :  0.1.82 : 0       : 82     : Import0 :  Visual Studio
[6] Comp ID: 0x6D81040101000000  :  33133.260.1 : 33133   : 1      : Utc1900_C :  Visual Studio 2015 14.00
[7] Comp ID: 0x6D81FF0001000000  :  33133.255.1 : 33133   : 1      : Cvtres1400 :  Visual Studio 2015 14.00
[8] Comp ID: 0x6D81020101000000  :  33133.258.1 : 33133   : 1      : Linker1400 :  Visual Studio 2015 14.00

##################       N T   H E A D E R       ##################

[*] NT HEADER                           @-- 0x26B400F8
[*] Signature                           @-- 0x4550

##################     F I L E   H E A D E R     ##################

[*] FILE HEADER                         @-- 0x79BCF340
[*] Machine                             @-- 0x8664
[*] No. of Sections                     @-- 10
[*] No. of Symbols                      @-- 0
[*] Pointer to Symbol Table             @-- 0x0
[*] Characteristics                     @-- 0x22
[*] Optional Header Size                @-- 0xF0

#################  O P T I O N A L   H E A D E R  #################

[*] OPTIONAL HEADER                     @-- 0x79BCF380
[*] Magic                               @-- 0x20B
[*] .text Size                          @-- 0x8A00
[*] .text Offset                        @-- 0x1000
[*] Entry Point                         @-- 0x1129E
[*] Base of Code                        @-- 0x1000
[*] Image Base                          @-- 0x40000000
[*] Rva & Sizes                         @-- 0x16
[*] MajorOSVersion                      @-- 0x6
[*] MinorOSVersion                      @-- 0x0
[*] MajorLinkerVersion                  @-- 0xE
[*] MinorLinkerVersion                  @-- 0x26
[*] MinorImageVersion                   @-- 0x0
[*] MinorImageVersion                   @-- 0x0
[*] Initialized Data Size               @-- 0x8000
[*] Uninitialized Data Size             @-- 0x0
[*] Size of Headers                     @-- 0x400
[*] Win32VersionValue                   @-- 0x0
[*] Subsystem                           @-- 0x3
[*] Image Size                          @-- 0x28000
[*] Checksum                            @-- 0x0

#################         S E C T I O N S         #################

______________  1: .textbss  ________________

[*] Raw Addr:           0x0
[*] Raw Size:           0x0
[*] Virtual Addr:       0x1000
[*] Virtual Size:       0x10000
[*] Characteristics:    0xE00000A0

[$] Has code; Uninitialized data; Read access;  Write access;  Can be executed as code;

______________  2: .text  ________________

[*] Raw Addr:           0x400
[*] Raw Size:           0x8A00
[*] Virtual Addr:       0x11000
[*] Virtual Size:       0x88CF
[*] Characteristics:    0x60000020

[$] Has code; Read access;  Can be executed as code;

______________  3: .rdata  ________________

[*] Raw Addr:           0x8E00
[*] Raw Size:           0x3400
[*] Virtual Addr:       0x1A000
[*] Virtual Size:       0x3399
[*] Characteristics:    0x40000040

[$] Has Initialized data; Read access;

______________  4: .data  ________________

[*] Raw Addr:           0xC200
[*] Raw Size:           0x200
[*] Virtual Addr:       0x1E000
[*] Virtual Size:       0x958
[*] Characteristics:    0xC0000040

[$] Has Initialized data; Read access;  Write access;

______________  5: .pdata  ________________

[*] Raw Addr:           0xC400
[*] Raw Size:           0x2200
[*] Virtual Addr:       0x1F000
[*] Virtual Size:       0x21A8
[*] Characteristics:    0x40000040

[$] Has Initialized data; Read access;

______________  6: .idata  ________________

[*] Raw Addr:           0xE600
[*] Raw Size:           0x1200
[*] Virtual Addr:       0x22000
[*] Virtual Size:       0x107F
[*] Characteristics:    0x40000040

[$] Has Initialized data; Read access;

______________  7: .msvcjmc─☺  ________________

[*] Raw Addr:           0xF800
[*] Raw Size:           0x200
[*] Virtual Addr:       0x24000
[*] Virtual Size:       0x1C4
[*] Characteristics:    0xC0000040

[$] Has Initialized data; Read access;  Write access;

______________  8: .00cfg  ________________

[*] Raw Addr:           0xFA00
[*] Raw Size:           0x200
[*] Virtual Addr:       0x25000
[*] Virtual Size:       0x175
[*] Characteristics:    0x40000040

[$] Has Initialized data; Read access;

______________  9: .rsrc  ________________

[*] Raw Addr:           0xFC00
[*] Raw Size:           0x600
[*] Virtual Addr:       0x26000
[*] Virtual Size:       0x43C
[*] Characteristics:    0x40000040

[$] Has Initialized data; Read access;

______________  10: .reloc  ________________

[*] Raw Addr:           0x10200
[*] Raw Size:           0x400
[*] Virtual Addr:       0x27000
[*] Virtual Size:       0x294
[*] Characteristics:    0x42000040

[$] Has Initialized data; Read access; Discardable
_______________________________________

#################         I M P O R T S           #################

[*] Data Directory                      @-- 0x79BCEBE0
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
