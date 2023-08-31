'''
The Telink encryption functions used in this project were pulled from Google's python-dimond project (NO LONGER USED)
    https://github.com/google/python-dimond
Code for changing Mesh Name and Password using factory settings was pulled from home-assistant-awox project (As well as new Telink packet functions)
    https://github.com/fsaris/home-assistant-awox
'''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_str
from bleak import BleakClient,BleakScanner
from bleak.exc import BleakError
#from Crypto.Cipher import AES #Not Needed???
#from Crypto.Random import get_random_bytes #Not needed???
from os import urandom
import base64
import binascii
import hashlib
import urllib
import packetutils as pckt
import requests
import struct
import json
import random
import time
import asyncio
import math

OPCODE_SETCOLOR = 0xe2
OPCODE_SETCCT = 0xf4
OPCODE_SETSTATE = 0xd0
OPCODE_SETBRIGHTNESS = 0xd0
OPCODE_SETFLASH = 0xd2
OPCODE_RESPONSE = 0xdc

C_GET_STATUS_SENT = 0xda        #Request current light/device status
C_GET_STATUS_RECEIVED = 0xdb    #Response of light/device status request
C_NOTIFICATION_RECEIVED = 0xdc  #State notification

STATEACTION_POWER = 0x01
STATEACTION_BRIGHTNESS = 0x02
STATEACTION_INCREASEBRIGHTNESS = 0x03
STATEACTION_DECREASEBRIGHTNESS = 0x04

COLORMODE_RGB = 0x60
COLORMODE_WARMWHITE = 0x61
COLORMODE_CCT = 0x62
COLORMODE_AUX = 0x63
COLORMODE_CCTAUX = 0x64

DIMMINGTARGET_RGBKWC = 0x01 #Set RGB, Keep WC
DIMMINGTARGET_WCKRGB = 0x02 #Set WC, Keep RGB
DIMMINGTARGET_RGBWC = 0x03  #Set RGB & WC
DIMMINGTARGET_RGBOWC = 0x04 #Set RGB, WC Off
DIMMINGTARGET_WCORGB = 0x05 #Set WC, RGB Off
DIMMINGTARGET_AUTO = 0x06   #Set lights according to situation

UUID_SERVICE_CONTROL = "00010203-0405-0607-0809-0a0b0c0d1910"
UUID_CONTROL = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_NOTIFY = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_PAIRING = "00010203-0405-0607-0809-0a0b0c0d1914"

UUID_SERVICE_DEVICEINFORMATION = "0000180a-0000-1000-8000-00805f9b34fb"
UUID_FIRMWARE = "00002a26-0000-1000-8000-00805f9b34fb"
UUID_MANUFACTURER = "00002a29-0000-1000-8000-00805f9b34fb"
UUID_MODEL = "00002a24-0000-1000-8000-00805f9b34fb"
UUID_HARDWARE = "00002a27-0000-1000-8000-00805f9b34fb"

global magichue_countryservers,magichue_usertoken,magichue_devicesecret,magichue_userid,magichue_getmeshendpoint,magichue_getmeshdevicesendpoint,magichue_meshes
magichue_countryservers = [{'nationName': 'Australian', 'nationCode': 'AU', 'serverApi': 'oameshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'oa.meshbroker.magichue.net'}, {'nationName': 'Avalon', 'nationCode': 'AL', 'serverApi': 'ttmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'tt.meshbroker.magichue.net'}, {'nationName': 'China', 'nationCode': 'CN', 'serverApi': 'cnmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'cn.meshbroker.magichue.net'}, {'nationName': 'England', 'nationCode': 'GB', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Espana', 'nationCode': 'ES', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'France', 'nationCode': 'FR', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Germany', 'nationCode': 'DE', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Italy', 'nationCode': 'IT', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Japan', 'nationCode': 'JP', 'serverApi': 'dymeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'dy.meshbroker.magichue.net'}, {'nationName': 'Russia', 'nationCode': 'RU', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'United States', 'nationCode': 'US', 'serverApi': 'usmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'us.meshbroker.magichue.net'}]
magichue_countryserver = magichue_countryservers[10]['serverApi']
magichue_connecturl = "http://" + magichue_countryserver
magichue_nationdataendpoint = "apixp/MeshData/loadNationDataNew/ZG?language=en"
magichue_userloginendpoint = "apixp/User001/LoginForUser/ZG"
magichue_getmeshendpoint = 'apixp/MeshData/GetMyMeshPlaceItems/ZG?userId='
magichue_getmeshdevicesendpoint = 'apixp/MeshData/GetMyMeshDeviceItems/ZG?placeUniID=&userId='
magichue_meshes = None
magichue_usertoken = None
magichue_devicesecret = None
magichue_userid = None


def convert_value_to_available_range(value, min_from, max_from, min_to, max_to) -> int:
    normalized = (value - min_from) / (max_from - min_from)
    new_value = min(
        round((normalized * (max_to - min_to)) + min_to),
        max_to,
    )
    return max(new_value, min_to)


def normal_round(n):
    if n - math.floor(n) < 0.5:
        return math.floor(n)
    return math.ceil(n)


def clamp(value, min_value, max_value):
    return max(min_value, min(max_value, value))


def saturate(value):
    return clamp(value, 0.0, 1.0)


def hue_to_rgb(h):
    r = abs(h * 6.0 - 3.0) - 1.0
    g = 2.0 - abs(h * 6.0 - 2.0)
    b = 2.0 - abs(h * 6.0 - 4.0)
    return saturate(r), saturate(g), saturate(b)


def hsl_to_rgb(h, s=1, l=.5):
    h = (h/360)
    r, g, b = hue_to_rgb(h)
    c = (1.0 - abs(2.0 * l - 1.0)) * s
    r = round((r - 0.5) * c + l,4) * 255
    g = round((g - 0.5) * c + l,4) * 255
    b = round((b - 0.5) * c + l,4) * 255
    if (r >= 250):
        r = 255
    if (g >= 250):
        g = 255
    if (b >= 250):
        b = 255
    return round(r), round(g), round(b)


def h360_to_h255(h360):
    if h360 <= 180:
        return normal_round((h360*254)/360)
    else:
        return normal_round((h360*255)/360)


def h255_to_h360(h255):
    if h255 <= 128:
        return normal_round((h255*360)/254)
    else:
        return normal_round((h255*360)/255)


def decode_color(color):
	red, green, blue = hsl_to_rgb(h255_to_h360(color))
	return red, green, blue


def generate_timestamp_checkcode():
    SECRET_KEY = "0FC154F9C01DFA9656524A0EFABC994F"
    timestamp = str(int(time.time()*1000))
    value = force_bytes("ZG" + timestamp)
    backend = default_backend()
    key = force_bytes(SECRET_KEY)
    encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).encryptor()
    padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
    padded_data = padder.update(value) + padder.finalize()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
    checkcode = binascii.hexlify(encrypted_text).decode()
    return timestamp,checkcode


def magichue_setcountryserver(countryCode=None): #{'nationName': 'United States', 'nationCode': 'US', 'serverApi': 'usmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'us.meshbroker.magichue.net'}
    global magichue_countryservers,magichue_nationdataendpoint,magichue_connecturl
    magichue_countryserver = magichue_countryservers[10]['serverApi'] #Default to USA server for pulling country list
    magichue_connecturl = "http://" + magichue_countryserver + magichue_nationdataendpoint
    headers = {
        'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
        'Accept-Language': 'en-US',
        'Accept': 'application/json',
        'token': '',
        'Accept-Encoding': 'gzip'
    }
    response = requests.get(magichue_connecturl, headers=headers)
    magichue_connecturl = None
    if response.status_code != 200:
        print('Failed to download Servers list - %s' % response.json()['error'])
        print('Defaulting to offline server data....\n')
        responseJSON = magichue_countryservers
        i = 0
        for nation in responseJSON:
            print (str(i) + ": " + nation['nationName'] + " - " + nation['serverApi'])
            i+=1
        country = int(input("Select Country for Server:"))
        magichue_connecturl = "http://" + magichue_countryservers[country]['serverApi']
        print("The default server has been set to " + magichue_countryservers[country]['nationCode'])
    else:
        print('Successfully downloaded Servers list!\n')
        responseJSON = response.json()['result']
        responseJSON.sort(key=lambda x: x["nationName"])
        magichue_countryservers = responseJSON
        if countryCode is None:
            i = 0
            for nation in responseJSON:
                print (str(i) + ": " + nation['nationName'] + " - " + nation['serverApi'])
                i+=1
            country = int(input("Select Country for Server:"))
            magichue_connecturl = "http://" + responseJSON[country]['serverApi']
            print("The default Hao Deng server has been set to " + responseJSON[country]['nationCode'] + " - " + magichue_connecturl)
        else:
            for nation in responseJSON:
                if nation['nationCode'] == countryCode.upper():
                    magichue_connecturl = "http://" + nation['serverApi']
                    print("The default server has been set to: " + countryCode.upper() + " - " + magichue_connecturl)
            if magichue_connecturl is None:
                print("MagicHue server was not found for " + countryCode.upper() + "\nDefaulting to US server...")
                magichue_connecturl = "http://" + magichue_countryservers[10]['serverApi']


def magichue_login(username, password):
    global magichue_usertoken,magichue_userid,magichue_devicesecret,magichue_connecturl,magichue_userloginendpoint
    timestamp_checkcode = generate_timestamp_checkcode()
    timestamp = timestamp_checkcode[0]
    checkcode = timestamp_checkcode[1]
    md5pass = hashlib.md5(password.encode()).hexdigest()
    payload = dict(userID=username, password=md5pass, appSys='Android', timestamp=timestamp, appVer='', checkcode=checkcode)
    headers = {
        'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
        'Accept-Language': 'en-US',
        'Accept': 'application/json',
        'token': '',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip'
    }
    response = requests.post(magichue_connecturl + magichue_userloginendpoint, headers=headers, json=payload)
    if response.status_code != 200:
        print('Login failure! - %s' % response.json()['error'])
    else:
        print('Login successful!')
        response_json = response.json()['result']
        magichue_userid = response_json['userId']
        magichue_usertoken = response_json['auth_token']
        magichue_devicesecret = response_json['deviceSecret']


def magichue_getmeshes():
    global magichue_connecturl,magichue_getmeshendpoint,magichue_userid,magichue_usertoken,magichue_meshes
    if magichue_usertoken is not None:
        headers = {
            'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
            'Accept-Language': 'en-US',
            'Accept': 'application/json',
            'token': magichue_usertoken,
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip'
        }
        response = requests.get(magichue_connecturl + magichue_getmeshendpoint + urllib.parse.quote_plus(magichue_userid), headers=headers)
        if response.status_code != 200:
            print('Get Mesh Settings web request failed! - %s' % response.json()['error'])
        else:
            print('Mesh settings retrieved successfully!')
            response_json = response.json()['result']
            magichue_meshes = response_json
            for mesh in magichue_meshes:
                mesh['devices'] = None
    else:
        print("Login session not detected! Please login first using MagicHue_Login method.")


def magichue_getmeshdevices():
    global magichue_connecturl,magichue_getmeshdevicesendpoint,magichue_userid,magichue_usertoken,magichue_meshes
    if magichue_usertoken is not None:
        headers = {
            'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
            'Accept-Language': 'en-US',
            'Accept': 'application/json',
            'token': magichue_usertoken,
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip'
        }
        for mesh in magichue_meshes:
            placeUniID = mesh['placeUniID']
            magichue_getmeshdevicesendpointnew = magichue_getmeshdevicesendpoint.replace("placeUniID=","placeUniID=" + placeUniID)
            magichue_getmeshdevicesendpointnew = magichue_getmeshdevicesendpointnew.replace("userId=","userId="+urllib.parse.quote_plus(magichue_userid))
            response = requests.get(magichue_connecturl + magichue_getmeshdevicesendpointnew, headers=headers)
            if response.status_code != 200:
                print('Mesh device retrieval FAILED for placeUniID: ' + placeUniID + ' - ' + response.json()['error'])
            else:
                print('Mesh devices retrieved for placeUniID: ' + placeUniID)
                responseJSON = response.json()['result']
                mesh.update({'devices':responseJSON})
    else:
        print("Login session not detected! Please login first using MagicHue_Login method.")


def magichue_listmeshes():
    for mesh in magichue_meshes:
        print("DisplayName: "+mesh['displayName'])
        print("PlaceUniID: "+mesh['placeUniID'])
        print("UserID: "+mesh['userID'])
        print("AccessType: "+str(mesh['accessType']))
        print("MeshKey: "+mesh['meshKey'])
        print("MeshPassword: "+mesh['meshPassword'])
        print("MeshLTK: "+mesh['meshLTK'])
        print("LastUpdateDate: "+mesh['lastUpdateDate'])
        print("MaxMeshAddress: "+str(mesh['maxMeshAddress']))
        print("MaxGroupID: "+str(mesh['maxGroupID']))
        print("")


def magichue_listmeshdevices():
    for mesh in magichue_meshes:
        print("Mesh DisplayName: "+mesh['displayName'])
        print("MeshKey: "+mesh['meshKey']+'\n')
        for device in mesh['devices']:
            print("\tDisplayName: "+device['displayName'])
            print("\tMACAddress: "+device['macAddress'])
            print("\tPlaceUniID: "+device['placeUniID'])
            print("\tMeshAddress: "+str(device['meshAddress']))
            print("\tMeshUUID: "+str(device['meshUUID']))
            print("\tDeviceType: "+str(device['deviceType']))
            print("\tWiringType: "+str(device['wiringType']))
            print("\tLastUpdateDate: "+device['lastUpdateDate'])
            print("")


class ZenggeMesh:
    def __init__(self, mac, mesh_name="ZenggeMesh", mesh_pass="ZenggeTechnology", mesh_ltk=None, mesh_id=0x0211):
        self.mac = mac
        self.mesh_id = mesh_id
        self.mesh_name = mesh_name
        self.mesh_pass = mesh_pass
        self.mesh_ltk = mesh_ltk
        self.client = None
        self.sk = None
        self.devices = []
        self.is_connected = False
    async def check_mesh_connection(self):
        if self.is_connected is False:
            print("Mesh is not connected! Connecting...")
            await self.connect()
    async def notification_handler(self, sender, data):
        """
        Simple notification handler which prints the data received.
        This will be modified later once Bleak implements a fix for start_notify issue.
        """
        print("{0}: {1}".format(sender, data))
        if self.sk is None:
            print(f'[{self.mesh_name}][{self.mac}] Device is disconnected, ignoring received notification [unable to decrypt without active session]')
            return
        message = pckt.decrypt_packet(self.sk, self.mac, data)
        if message is None:
            print(f'[{self.mesh_name}][{self.mac}] Failed to decrypt package [key: {self.sk}, data: {data}]')
            return
        print(f'Unencrypted packet: [data: {repr(list(message))}]')
        self._parse_status_result(message)
    def _parse_status_result(self, data):
        command = struct.unpack('B', data[7:8])[0]
        status = {}
        if command == C_GET_STATUS_RECEIVED: #This does not return anything useful other than device is online/talking to mesh
            mesh_address = struct.unpack('B', data[3:4])[0]
        if command == C_NOTIFICATION_RECEIVED:
            mesh_address = struct.unpack('B', data[10:11])[0] #Device ID should only be data[10:11]
            mode = struct.unpack('B', data[13:14])[0] #Mode is [13:14][0]
            brightness = struct.unpack('B', data[12:13])[0] #should be [12:13][0]
            white_temperature = color = struct.unpack('B', data[14:15])[0] #should be [14:15][0]
            if(mode == 63 or mode == 42):
                color_mode = 'rgb'
                rgb = decode_color(color) #Converts from 1 value(kelvin) to RGB
            else:
                color_mode = 'white'
                rgb = [0,0,0]
            status = {
                'type': 'notification',
                'mesh_address': mesh_address,
                'state': brightness != 0,
                'color_mode': color_mode,
                'rgb': rgb,
                'white_temperature': white_temperature,
                'brightness': brightness,
            }
        if status:
            print(f'[{self.mesh_name}][{self.mac}] Parsed status: {status}')
        else:
            print(f'[{self.mesh_name}][{self.mac}] Unknown command [{command}]')
        #if status and status['mesh_id'] == self.mesh_id:
        #    print(f'[{self.mesh_name}][{self.mac}] Update device status - mesh_id: {status["mesh_id"]}')
        #    self.state = status['state']
        #    self.color_mode = status['color_mode']
        #    self.brightness = status['brightness']
        #    self.white_temperature = status['white_temperature']
        #    self.rgb = status['rgb']
        #if status and self.status_callback:
        #    self.status_callback(status)
    async def enableNotify(self): #Huge thanks to 'cocoto' for helping me figure out this issue with Zengge!!
        await self.check_mesh_connection()
        await self.send_packet(0x01,bytes([]),self.mesh_id,uuid=UUID_NOTIFY)
        print("Enable notify packet sent2...")
        await self.client.start_notify(UUID_NOTIFY, self.notification_handler)
    async def mesh_login(self):
        if self.client == None:
            return
        session_random = urandom(8)
        message = pckt.make_pair_packet(self.mesh_name.encode(), self.mesh_pass.encode(), session_random)
        pairReply = await self.client.write_gatt_char(UUID_PAIRING, bytes(message), True)
        await asyncio.sleep(0.3)
        reply = await self.client.read_gatt_char(UUID_PAIRING)
        self.sk = pckt.make_session_key(self.mesh_name.encode(), self.mesh_pass.encode(), session_random, reply[1:9])
    async def send_packet(self, command, data, dest=None, withResponse=True, attempt=0, uuid=UUID_CONTROL):
        """
        Args:
            command: The command, as a number.
            data: The parameters for the command, as bytes.
            dest: The destination mesh id, as a number. If None, this lightbulb's
                mesh id will be used.
        """
        assert (self.sk)
        if dest == None: dest = self.mesh_id
        packet = pckt.make_command_packet(self.sk, self.mac, dest, command, data)
        try:
            print(f'[{self.mesh_name}][{self.mac}] Writing command {command} data {repr(data)}')
            return await self.client.write_gatt_char(uuid, packet)
        except Exception as err:
            print(f'[{self.mesh_name}][{self.mac}] Command failed, attempt: {attempt} - [{type(err).__name__}] {err}')
            if attempt < 2:
                self.connect()
                return self.send_packet(command, data, dest, withResponse, attempt+1)
            else:
                self.sk = None
                raise err
    async def read_gatt_char(self, char):
        assert (self.sk)
        reply = await self.client.read_gatt_char(char)
        return reply
    async def connect(self):
        try:
            device = await BleakScanner.find_device_by_address(self.mac, timeout=10.0)
            if not device:
                raise BleakError(f"A device with address {self.mac} could not be found.")
            self.client = BleakClient(self.mac)
            await self.client.connect()
            print("Connected to device!")
            await self.mesh_login()
            if self.sk is None:
                raise Exception(f"Mesh login failed!")
            else:
                print("Mesh login success!")
            self.is_connected = True
            await self.enableNotify() #This will be modified later once Bleak implements a fix for start_notify issue.
            print("Notify enabled successfully!")
        except Exception as e:
            print(f"Connection to {self.mac} failed!\nError: {e}")
            self.is_connected = False
            self.client = None
            self.sk = None
            pass
        if self.client is None or self.sk is None:
            raise Exception(f"Unable to connect to mesh {self.mesh_name} via {self.mac}")
    async def setMesh(self, new_mesh_name, new_mesh_password, new_mesh_long_term_key):
        """
        Sets or changes the mesh network settings.

        Args :
            new_mesh_name: The new mesh name as a string, 16 bytes max.
            new_mesh_password: The new mesh password as a string, 16 bytes max.
            new_mesh_long_term_key: The new long term key as a string, 16 bytes max.

        Returns :
            True on success.
        """
        assert (self.sk), "Not connected"
        assert len(new_mesh_name.encode()) <= 16, "new_mesh_name can hold max 16 bytes"
        assert len(new_mesh_password.encode()) <= 16, "new_mesh_password can hold max 16 bytes"
        assert len(new_mesh_long_term_key.encode()) <= 16, "new_mesh_long_term_key can hold max 16 bytes"
        if self.sk is None:
            print("BLE device is not connected!")
            self.mac = input('Please enter MAC of device:')
            self.connect()
        message = pckt.encrypt(self.sk, new_mesh_name.encode())
        message.insert(0, 0x4)
        await self.client.write_gatt_char(UUID_PAIRING, message)
        message = pckt.encrypt(self.sk, new_mesh_password.encode())
        message.insert(0, 0x5)
        await self.client.write_gatt_char(UUID_PAIRING, message)
        message = pckt.encrypt(self.sk, new_mesh_long_term_key.encode())
        message.insert(0, 0x6)
        await self.client.write_gatt_char(UUID_PAIRING, message)
        asyncio.sleep(1)
        reply = bytearray(await self.client.read_gatt_char(UUID_PAIRING))
        if reply[0] == 0x7:
            self.mesh_name = new_mesh_name
            self.mesh_pass = new_mesh_password
            print(f'[{self.mesh_name}]-[{self.mesh_pass}]-[{self.mac}] Mesh network settings accepted.')
            return True
        else:
            print(f'[{self.mesh_name}][{self.mac}] Mesh network settings change failed : {repr(reply)}')
            return False
    async def disconnect(self):
        self.is_connected = False
        self.sk = None
        await self.client.disconnect()
        print("Device disconnected!")


class ZenggeLight:
    def __init__(self, display_name, mesh_address, mac, device_type, control_type=None, wiring_type=None, ota_flag=None, place_id=None, mesh=None):
        self.display_name = display_name
        self.mesh_address = mesh_address
        self.mac = mac
        self.device_type = device_type
        self.control_type = control_type
        self.wiring_type = wiring_type
        self.ota_flag = ota_flag
        self.place_id = place_id
        self.mesh = mesh
        self.mesh_id = None if mesh is None else mesh.mesh_id
        self.state = 0
        self.brightness = 0
        self.temperature = 0
        self.rgb = [0,0,0]
        self.is_connected = False
    async def check_mesh_connection(self):
        if self.mesh.is_connected is False:
            print("Mesh is not connected! Connecting...")
            await self.mesh.connect()
    async def light_on(self):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,STATEACTION_POWER,1])
        await self.mesh.send_packet(OPCODE_SETSTATE,packetData,self.mesh_address)
        self.state = 1
    async def light_off(self):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,STATEACTION_POWER,0])
        await self.mesh.send_packet(OPCODE_SETSTATE,packetData,self.mesh_address)
        self.state = 0
    async def light_toggle(self):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,STATEACTION_POWER,self.state^1])
        await self.mesh.send_packet(OPCODE_SETSTATE,packetData,self.mesh_address)
        self.state = self.state^1
    #Brightness value accepts 0-100 (0 is off) *required*
    #Dimming target specifies dimming of RGB LEDs vs White LEDs
    #Delay is in 100ms units *Default is 0-No delay* (Max value is 65535
    #Gradient is in 100ms units *Default is 0-No gradient*
    async def light_brightness(self, value=1,dimmingTarget=DIMMINGTARGET_RGBWC,delay=0,gradient=0):
        await self.check_mesh_connection()
        delay0 = format(delay,'b').zfill(16)
        delayLB = int(delay0[8:16],2)
        delayHB = int(delay0[0:8],2)
        gradient0 = format(gradient,'b').zfill(16)
        gradientLB = int(gradient0[8:16],2)
        gradientHB = int(gradient0[0:8],2)
        packetData = bytes([self.device_type,STATEACTION_BRIGHTNESS,value,dimmingTarget,delayLB,delayHB,gradientLB,gradientHB])
        await self.mesh.send_packet(OPCODE_SETBRIGHTNESS,packetData,self.mesh_address)
        self.brightness = value
    # Change mode of light (RGB, Warm, CCT/Lum, AuxLight, ColorTemp/Lum/AuxLight)
    #   0x60 is the mode for static RGB (Value1,Value2,Value3 stand for RGB values 0-255)
    #   0x61 stands for static warm white (Value1 represents warm white value 0-255)
    #   0x62 stands for color temp/luminance (Value1 represents CCT scale value 0-100, Value2 represents luminance value 0-100)
    #   0x63 stands for auxiliary light (Value1 represents aux light brightness)
    #   0x64 stands for color temp value + aux light (Value1 represents CCT ratio value 1-100, Value 2 represents luminance value 0-100, Value 3 represents aux luminance value 0-100)
    async def light_rgb(self, r=0,g=0,b=0):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,COLORMODE_RGB,r,g,b])
        await self.mesh.send_packet(OPCODE_SETCOLOR,packetData,self.mesh_address)
        self.rgb = r,g,b
    async def light_warmwhite(self, lum=0):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,COLORMODE_WARMWHITE,lum])
        await self.mesh.send_packet(OPCODE_SETCOLOR,packetData,self.mesh_address)
        self.temperature = lum
        self.rgb = [0,0,0]
    async def light_cct(self, cct=0,lum=0):
        await self.check_mesh_connection()
        packetData = bytes([self.device_type,COLORMODE_CCT,cct,lum])
        await self.mesh.send_packet(OPCODE_SETCOLOR,packetData,self.mesh_address)
        self.temperature = cct
        self.brightness = lum
        self.rgb = [0,0,0]