ZengeeBLEMeshBleak
=========================================
Ported Google's python-dimond library from bluepy to Bleak for use with Zengee BLE mesh devices. Ultimate goal is Zengee Home Assistant integration.

Requirements
------------
bleak<br/>
pycryptodome<br/>

Example use
-----------
#(Device/Mesh info was pulled from Zengge app database (ZGMeshDB) using a rooted Android device)<br/>
#Location of values are in parentheses as (DB Table - DB Column)<br/>
import Zengge_Bleak<br/>
import asyncio<br/>
import time<br/>
<br/>
vendorID = 0x0211 #(MeshDevice - meshUUID)<br/>
meshName = "q31k125n759z2fkn" #(MeshPlace - meshKey)<br/>
meshPass = "4rie6o2dl56fz2ui" #(MeshPlace - meshPassword)<br/>
<br/>
deviceMAC = "08:65:F0:05:24:42"    #(MeshDevice - macAddress)<br/>
deviceName = "Light1" #This is not required<br/>
deviceID = 0x03       #(MeshDevice - meshAddress)<br/>
deviceType = 0x41     #(MeshDevice - deviceType)<br/>
<br/>
mesh = Zengge_Bleak.ZenggeMesh(vendorID, deviceMAC, meshName, meshPass)<br/>
device = Zengge_Bleak.ZenggeLight("Light1",0x03,deviceMAC,0x41,mesh)<br/>
<br/>
async def execute():<br/>
    await mesh.connect()<br/>
    await device.light_on()<br/>
    await device.light_RGB(255,0,0)<br/>
    time.sleep(3)<br/>
    await device.light_off()<br/>
    await mesh.disconnect()<br/>
<br/>
asyncio.run(execute())<br/>
