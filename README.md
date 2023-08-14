ZengeeBLEMeshBleak
=========================================
Ported Google's python-dimond library from bluepy to Bleak for use with Zengee BLE mesh devices. Ultimate goal is Zengee Home Assistant integration.<br/>

Requirements
------------
bleak<br/>
pycryptodome<br />

Zengge App Database (ZGMeshDB)
-----------
The communication to your Zengge BLE Mesh device is encrypted.<br/>
You will need to pull the encryption keys from the ZGMeshDB database on your phone after pairing.<br/><br/>
On a rooted Android device, the ZGMeshDB database file can be found here:<br/>
/data/data/com.zengge.telinkmeshlight/databases/ZGMeshDB<br/>

I believe there is a way to pair and generate encryption keys from your computer to bypass the above. I am looking into this.<br/>

I have included the DB location of the device/mesh values you need in the example below in the following format:<br/>
(DB Table - DB Column)<br/>

Example - Control lights
----------------------------
```
import Zengge_Bleak
import asyncio
import time

meshID = 0x0211                   #(MeshDevice - meshUUID)
meshName = "q31k125n759z2fkn"     #(MeshPlace - meshKey)
meshPass = "4rie6o2dl56fz2ui"     #(MeshPlace - meshPassword)
meshLTK = "83dd4d4630f5h57g"      #This is not required

deviceMAC = "08:65:F0:05:25:65"   #(MeshDevice - macAddress)
deviceName = "Light1"             #This is not required
deviceID = 0x05                   #(MeshDevice - meshAddress)
deviceType = 0x41                 #(MeshDevice - deviceType)

mesh = Zengge_Bleak.ZenggeMesh(deviceMAC, meshID, meshName, meshPass, meshLTK)
device = Zengge_Bleak.ZenggeLight("Light1",0,deviceID,deviceMAC,deviceType,0,0,0,0,mesh)

async def execute():
    await mesh.connect()
    await device.light_on()
    await device.light_RGB(255,0,0)
    time.sleep(3)
    await device.light_off()
    await mesh.disconnect()

asyncio.run(execute())
```

Example - Pull Mesh Settings from Hao Deng Server
----------------------------------------
```
import Zengge_Bleak
Zengge_Bleak.HaoDeng_SetCountryServer("US")
Zengge_Bleak.HaoDeng_Login("usernameHere", "passwordHere")
zenggeMesh = Zengge_Bleak.HaoDeng_GetMesh()
zenggeMesh
```

Current issues
---------------
One main issue with the Bleak library is the inability to subscribe to notifications on a GATT server that has been misconfigured (Does not follow BLE RFC specs).
Unfortunately, the Zengge floodlight that I have been testing with does not follow RFC spec so notifications are broken in my code.

The only real problem I found with this was the inability to retrieve real-time status updates from the device.
You can still send command packets and *assume* they are received and processed.
