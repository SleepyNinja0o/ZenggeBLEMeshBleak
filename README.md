ZenggeBLEMeshBleak
=========================================
Building a python module for controlling Zengge BLE mesh devices using Bleak as the backend.<br/>
Ultimate goal is Zengge Home Assistant integration.<br/>

Requirements
------------
cryptography<br/>
requests <br/>
django<br/>
bleak<br/>
<br/>
<br/>
Install via PowerShell using:<br/>
```
("cryptography","requests","django","bleak") | foreach {pip install $_}
```

Example - Pull Mesh Information from MagicHue Server (aka 'ZenggeCloud' in script)
----------------------------------------
```
#Supported country servers are: (Defaults to US)
  AU AL CN GB ES FR DE IT JP RU US

from zengge_bleak import ZenggeCloud
zenggeCloud = ZenggeCloud(username="usernameHere",password="passwordHere",country="US")
zenggeCloud.magichue_listmeshes()
zenggeCloud.magichue_listmeshdevices()
```

Example - Control Lights
----------------------------
```
import zengge_bleak
import asyncio

meshID = 0x0211                   #(MeshDevice - meshUUID)
meshName = "q31k125n759z2fkn"     #(MeshPlace - meshKey)
meshPass = "4rie6o2dl56fz2ui"     #(MeshPlace - meshPassword)
meshLTK = "83dd4d4630f5h57g"      #This is not required

deviceName = "Light1"             #This is not required
deviceMAC = "08:65:F0:05:25:65"   #(MeshDevice - macAddress)
deviceMeshAddress = 0x05          #(MeshDevice - meshAddress)
deviceType = 0x41                 #(MeshDevice - deviceType)

mesh = zengge_bleak.ZenggeMesh(deviceMAC, meshName, meshPass, meshLTK, meshID)
device = zengge_bleak.ZenggeLight(deviceName,deviceMeshAddress,deviceMAC,deviceType,0,0,0,0,mesh)

async def execute():
    await mesh.connect()
    await device.light_on()
    await device.light_rgb(255,0,0)
    await asyncio.sleep(3)
    await device.light_off()
    await asyncio.sleep(10) #Test notifications here
    await mesh.disconnect()

asyncio.run(execute())
```
