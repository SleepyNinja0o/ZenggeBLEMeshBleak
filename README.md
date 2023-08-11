ZengeeBLEMeshBleak
=========================================
Ported Google's python-dimond library from bluepy to Bleak for use with Zengee BLE mesh devices. Ultimate goal is Zengee Home Assistant integration.

Requirements
------------
bleak
pycryptodome

Example use
-----------
#(Device/Mesh info was pulled from Zengge app database (ZGMeshDB) using a rooted Android device)
#Location of values are in parentheses as (DB Table - DB Column)
import Zengge_Bleak
import asyncio
import time

vendorID = 0x0211 #(MeshDevice - meshUUID)
meshName = "q31k125n759z2fkn" #(MeshPlace - meshKey)
meshPass = "4rie6o2dl56fz2ui" #(MeshPlace - meshPassword)

deviceMAC = "08:65:F0:05:24:42"    #(MeshDevice - macAddress)
deviceName = "Light1" #This is not required
deviceID = 0x03       #(MeshDevice - meshAddress)
deviceType = 0x41     #(MeshDevice - deviceType)

mesh = Zengge_Bleak.ZenggeMesh(vendorID, deviceMAC, meshName, meshPass)
device = Zengge_Bleak.ZenggeLight("Light1",0x03,deviceMAC,0x41,mesh)

async def execute():
    await mesh.connect()
    await device.light_on()
    await device.light_RGB(255,0,0)
    time.sleep(3)
    await device.light_off()
    await mesh.disconnect()

asyncio.run(execute())
