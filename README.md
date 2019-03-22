pe-afl combines static binary instrumentation on PE binary and WinAFL

so that it can fuzz on windows user-mode application and kernel-mode driver without source or full symbols or hardware support

details, benchmark and some kernel-mode case study can be found on [slide](https://www.slideshare.net/wmliang/make-static-instrumentation-great-again-high-performance-fuzzing-for-windows-system) and [video](https://www.youtube.com/watch?v=OipNF8v2His), which is presented on BluehatIL 2019

it is not so reliable and dirty, but it works and high-performance

i reported bugs on office,gdiplus,jet,lnk,clfs,cng,hid by using this tool

the instrumentation part on PE can be reused on many purpose

ps1. if you feel slow on instrumenting, you can run the script on ubuntu

ps2. the instrument is based on microsoft binary and the binary compiled by visual studio, so it may fail on non-microsoft compiler

## How-to instrument

**example to instrument 2 NOP on entry point of calc.exe**

```
ida.exe demo\calc.exe
# loading with pdb is more reliable if pdb is available

File->script file->ida_dump.py

python instrument.py -i"{0x1012d6c:'9090'}" demo\calc.exe demo\calc.exe.dump.txt
# 0x1012d6c is entry point address, you can instrument from command-line or from __main__ in instrument.py
```

## How-to fuzz

you have to implement the wrapper/harness (AFL\test_XXX\) depends on target

and add anything you want, such page heap, etc

**instrument JetDB for fuzzing**

```
ida.exe demo\msjet40.dll

File->script file->ida_dump.py

python pe-afl.py -m demo\msjet40.dll demo\msjet40.dll.dump.txt
# msjet40 is multi-thread, so -m is here
```

**fuzz JetDB on win7**

```
copy /Y msjet40.instrumented.dll C:\Windows\System32\msjet40.dll

bin\afl-showmap.exe -o NUL -p msjet40.dll -- bin\test_mdb.exe demo\mdb\normal.mdb
# make sure that capture is OK

bin\AFL.exe -i demo\mdb -o out -t 5000 -m none -p msjet40.dll -- bin\test_mdb.exe @@
```

**instrument CLFS for fuzzing**

```
ida.exe demo\clfs.sys
File->script file->ida_dump.py

python pe-afl.py demo\clfs.sys demo\clfs.sys.dump.txt
```

**fuzz CLFS on win10**

```
install_helper.bat
disable_dse.bat
copy /Y clfs.instrumented.sys C:\Windows\System32\drivers\clfs.sys
# reboot if necessary
	
bin\afl-showmap.exe -o NUL -p clfs.sys -- bin\test_clfs.exe demo\blf\normal.blf
# make sure that capture is OK
	
bin\AFL.exe -i demo\blf -o out -t 5000 -m none -p clfs.sys -- bin\test_clfs.exe @@
```

## How-to trace

**example to log driver execution trace and import into lighthouse**

```
ida.exe demo\clfs.sys
File->script file->ida_dump.py

python pe-afl.py -cb demo\clfs.sys demo\clfs.sys.dump.txt
copy /Y clfs.instrumented.sys C:\Windows\System32\drivers\clfs.sys
# reboot if necessary

bin\afl-showmap.exe -o NUL -p clfs.sys -d -- bin\test_clfs.exe demo\blf\normal.blf
# output is trace.txt

python lighthouse_trace.py demo\clfs.sys demo\clfs.sys.mapping.txt trace.txt > trace2.txt

# install lighthouse
xcopy /y /e lighthouse [IDA folder]\plugins\

ida.exe demo\clfs.sys
File->Load File->Code coverage file->trace2.txt
```

## TODO

support x64
