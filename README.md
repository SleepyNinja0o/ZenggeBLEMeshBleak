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

Example use - Windows
----------------------
```
import Zengge_Bleak
import asyncio
import time

vendorID = 0x0211                 #(MeshDevice - meshUUID)
meshName = "q31k125n759z2fkn"     #(MeshPlace - meshKey)
meshPass = "4rie6o2dl56fz2ui"     #(MeshPlace - meshPassword)

deviceMAC = "08:65:F0:05:24:42"   #(MeshDevice - macAddress)
deviceName = "Light1"             #This is not required
deviceID = 0x03                   #(MeshDevice - meshAddress)
deviceType = 0x41                 #(MeshDevice - deviceType)

mesh = Zengge_Bleak.ZenggeMesh(vendorID, deviceMAC, meshName, meshPass)
device = Zengge_Bleak.ZenggeLight(deviceName,deviceID,deviceMAC,deviceType,mesh)

async def execute():
    await mesh.connect()
    await device.light_on()
    await device.light_RGB(255,0,0)
    time.sleep(3)
    await device.light_off()
    await mesh.disconnect()

asyncio.run(execute())
```
