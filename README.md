ZengeeBLEMeshBleak
=========================================
Building a python module for controlling Zengee BLE mesh devices using Bleak as the backend.<br/>
Ultimate goal is Zengee Home Assistant integration.<br/>

Requirements
------------
pycryptodome<br/>
cryptography<br/>
requests <br/>
django<br/>
bleak<br/>
<br/>
<br/>
Install via PowerShell using:<br/>
```
("pycryptodome","cryptography","requests","django","bleak") | foreach {pip install $_}
```

Example - Pull Mesh Information from MagicHue Server
----------------------------------------
```
import Zengge_Bleak
Zengge_Bleak.MagicHue_SetCountryServer("US")
Zengge_Bleak.MagicHue_Login("usernameHere", "passwordHere")

Zengge_Bleak.MagicHue_GetMeshes()       #Saved to global variable 'magichue_meshes'
Zengge_Bleak.MagicHue_GetMeshDevices()  #Saved to 'devices' attribute under global variable 'magichue_meshes'

Zengge_Bleak.MagicHue_ListMeshes()
Zengge_Bleak.MagicHue_ListMeshDevices()
```

Example - Control Lights
----------------------------
```
import Zengge_Bleak
import asyncio

meshID = 0x0211                   #(MeshDevice - meshUUID)
meshName = "q31k125n759z2fkn"     #(MeshPlace - meshKey)
meshPass = "4rie6o2dl56fz2ui"     #(MeshPlace - meshPassword)
meshLTK = "83dd4d4630f5h57g"      #This is not required

deviceName = "Light1"             #This is not required
deviceMAC = "08:65:F0:05:25:65"   #(MeshDevice - macAddress)
deviceMeshAddress = 0x05          #(MeshDevice - meshAddress)
deviceType = 0x41                 #(MeshDevice - deviceType)

mesh = Zengge_Bleak.ZenggeMesh(deviceMAC, meshID, meshName, meshPass, meshLTK)
device = Zengge_Bleak.ZenggeLight(deviceName,deviceMeshAddress,deviceMAC,deviceType,0,0,0,0,mesh)

async def execute():
    await mesh.connect()
    await device.light_on()
    await device.light_RGB(255,0,0)
    await asyncio.sleep(3)
    await device.light_off()
    await asyncio.sleep(10) #Test notifications here
    await mesh.disconnect()

asyncio.run(execute())
```
