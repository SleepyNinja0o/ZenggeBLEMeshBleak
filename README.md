ZenggeBLEMeshBleak
=========================================
Building a python module for controlling Zengge BLE mesh devices using Bleak as the backend.<br/>
Ultimate goal is Zengge Home Assistant integration.<br/>

Requirements
------------
cryptography<br/>
requests <br/>
bleak<br/>

Example - Pull Mesh Information from Cloud
----------------------------------------
```
#Supported country servers are: (Defaults to US)
  AU AL CN GB ES FR DE IT JP RU US

from zengge_bleak import *
zengge_cloud = ZenggeCloud("usernameHere","passwordHere","US")  #Login and data retrieval happens on init
zengge_cloud.list_meshes()
zengge_cloud.list_mesh_devices()
```

Example - Control Lights
----------------------------
```
from zengge_bleak import *
import asyncio

meshID = 0x0211
meshName = "q31k125n759z2fkn"
meshPass = "4rie6o2dl56fz2ui"
meshLTK = "83dd4d4630f5h57g"

deviceName = "Light1"
deviceMAC = "08:65:F0:05:25:65"
deviceMeshAddress = 0x05
deviceType = 0x41

mesh = ZenggeMesh(deviceMAC, meshName, meshPass, meshLTK, meshID)
device = ZenggeLight(deviceName,deviceMeshAddress,deviceMAC,deviceType,0,0,0,0,mesh)

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
