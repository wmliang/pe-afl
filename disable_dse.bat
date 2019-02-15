copy bin\winload2.exe C:\Windows\system32\winload2.exe
bcdedit /set recoveryenabled no
bcdedit /set nointegritychecks on
bcdedit /set path \Windows\system32\winload2.exe

rem it would be better to patch winload yourself, due to different version
