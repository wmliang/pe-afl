copy helper\Release_win10\helper.sys C:\Windows\system32\drivers\helper.sys
sc create helper binPath= "C:\Windows\system32\drivers\helper.sys"  type= "kernel" start= "system" error= "normal" Displayname= "helper"
sc start helper
