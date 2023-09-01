'''
Code for Telink packet encrpytion functions & changing Mesh Name + Password using factory settings was pulled from home-assistant-awox project
    https://github.com/fsaris/home-assistant-awox
'''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from bleak import BleakClient,BleakScanner
from bleak.exc import BleakError
from os import urandom
import binascii
import hashlib
import urllib
import packetutils as pckt
import requests
import struct
import time
import asyncio
import math

OPCODE_SETCOLOR = 0xe2
OPCODE_SETCCT = 0xf4
OPCODE_SETSTATE = 0xd0
OPCODE_SETBRIGHTNESS = 0xd0
OPCODE_SETFLASH = 0xd2

OPCODE_GET_STATUS = 0xda        #Request current light/device status
OPCODE_STATUS_RECEIVED = 0xdb    #Response of light/device status request
OPCODE_NOTIFICATION_RECEIVED = 0xdc  #State notification
OPCODE_RESPONSE = 0xdc

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

ZENGGE_MAC_OUI_1 = "08:65:F0"
ZENGGE_MAC_OUI_2 = "F8:6D:73"

class ZenggeColor:
    def __new__():
        raise TypeError("This is a static class and cannot be initialized.")
    
    @staticmethod
    def _normal_round(n):
        if n - math.floor(n) < 0.5:
            return math.floor(n)
        return math.ceil(n)
    
    @staticmethod
    def _clamp(value, min_value, max_value):
        return max(min_value, min(max_value, value))
    
    @staticmethod
    def _saturate(value):
        return ZenggeColor._clamp(value, 0.0, 1.0)
    
    @staticmethod
    def _hue_to_rgb(h):
        r = abs(h * 6.0 - 3.0) - 1.0
        g = 2.0 - abs(h * 6.0 - 2.0)
        b = 2.0 - abs(h * 6.0 - 4.0)
        return ZenggeColor._saturate(r), ZenggeColor._saturate(g), ZenggeColor._saturate(b)
    
    @staticmethod
    def _hsl_to_rgb(h, s=1, l=.5):
        h = (h/360)
        r, g, b = ZenggeColor._hue_to_rgb(h)
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
    
    @staticmethod
    def _h360_to_h255(h360):
        if h360 <= 180:
            return ZenggeColor._normal_round((h360*254)/360)
        else:
            return ZenggeColor._normal_round((h360*255)/360)
    
    @staticmethod
    def _h255_to_h360(h255):
        if h255 <= 128:
            return ZenggeColor._normal_round((h255*360)/254)
        else:
            return ZenggeColor._normal_round((h255*360)/255)
    
    @staticmethod
    def decode(color):
        return ZenggeColor._hsl_to_rgb(ZenggeColor._h255_to_h360(color))


class ZenggeCloud:
    def __init__(self, username, password, country="US"):
        self._username = username
        self._password = hashlib.md5(password.encode()).hexdigest()
        self._magichue_usertoken = None
        self._magichue_devicesecret = None
        self.magichue_userid = None
        self.magichue_meshes = None
        self.magichue_countryservers = [{'nationName': 'Australian', 'nationCode': 'AU', 'serverApi': 'oameshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'oa.meshbroker.magichue.net'}, {'nationName': 'Avalon', 'nationCode': 'AL', 'serverApi': 'ttmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'tt.meshbroker.magichue.net'}, {'nationName': 'China', 'nationCode': 'CN', 'serverApi': 'cnmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'cn.meshbroker.magichue.net'}, {'nationName': 'England', 'nationCode': 'GB', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Espana', 'nationCode': 'ES', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'France', 'nationCode': 'FR', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Germany', 'nationCode': 'DE', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Italy', 'nationCode': 'IT', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'Japan', 'nationCode': 'JP', 'serverApi': 'dymeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'dy.meshbroker.magichue.net'}, {'nationName': 'Russia', 'nationCode': 'RU', 'serverApi': 'eumeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'eu.meshbroker.magichue.net'}, {'nationName': 'United States', 'nationCode': 'US', 'serverApi': 'usmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'us.meshbroker.magichue.net'}]
        self.magichue_connecturl = self._get_magichue_countryserver() if country=="US" else self._get_magichue_countryserver(country) #Default to US server
        login = self.login()
        if login == True:
            self.get_meshes()
            self.get_mesh_devices()
    
    def _get_magichue_countryserver(self, country="US"):
        for item in self.magichue_countryservers:
            if(item['nationCode'] == country.upper()):
                return ("http://" + item['serverApi'])
        return ("http://" + self._magichue_countryservers[10]['serverApi']) #Return US server if error
    
    def _generate_timestamp_checkcode(self):
        SECRET_KEY = "0FC154F9C01DFA9656524A0EFABC994F"
        timestamp = str(int(time.time()*1000))
        value = ("ZG" + timestamp).encode()
        backend = default_backend()
        key = (SECRET_KEY).encode()
        encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).encryptor()
        padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
        checkcode = binascii.hexlify(encrypted_text).decode()
        return timestamp,checkcode
    
    def login(self):
        timestamp_checkcode = self._generate_timestamp_checkcode()
        timestamp = timestamp_checkcode[0]
        checkcode = timestamp_checkcode[1]
        payload = dict(userID=self._username, password=self._password, appSys='Android', timestamp=timestamp, appVer='', checkcode=checkcode)
        headers = {
            'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
            'Accept-Language': 'en-US',
            'Accept': 'application/json',
            'token': '',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip'
        }
        magichue_userloginendpoint = "apixp/User001/LoginForUser/ZG"
        response = requests.post(self.magichue_connecturl + magichue_userloginendpoint, headers=headers, json=payload)
        if response.status_code != 200:
            print('Login failure! - %s' % response.json()['error'])
            return False
        else:
            print('Login successful!')
            response_json = response.json()['result']
            self.magichue_userid = response_json['userId']
            self._magichue_usertoken = response_json['auth_token']
            self._magichue_devicesecret = response_json['deviceSecret']
            return True
    
    def get_meshes(self):
        if self._magichue_usertoken is not None:
            headers = {
                'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
                'Accept-Language': 'en-US',
                'Accept': 'application/json',
                'token': self._magichue_usertoken,
                'Content-Type': 'application/json',
                'Accept-Encoding': 'gzip'
            }
            magichue_meshendpoint = "apixp/MeshData/GetMyMeshPlaceItems/ZG?userId="
            response = requests.get(self.magichue_connecturl + magichue_meshendpoint + urllib.parse.quote_plus(self.magichue_userid), headers=headers)
            if response.status_code != 200:
                print('Get Mesh Settings web request failed! - %s' % response.json()['error'])
                return False
            else:
                print('Mesh settings retrieved successfully!')
                response_json = response.json()['result']
                self.magichue_meshes = response_json
                for mesh in self.magichue_meshes:
                    mesh['devices'] = None
                return True
        else:
            print("Login session not detected! Please login first using MagicHue_Login method.")
            return False
    
    def get_mesh_devices(self):
        if self._magichue_usertoken is not None:
            headers = {
                'User-Agent': 'HaoDeng/1.5.7(ANDROID,10,en-US)',
                'Accept-Language': 'en-US',
                'Accept': 'application/json',
                'token': self._magichue_usertoken,
                'Content-Type': 'application/json',
                'Accept-Encoding': 'gzip'
            }
            for mesh in self.magichue_meshes:
                placeUniID = mesh['placeUniID']
                magichue_meshdevicesendpoint = "apixp/MeshData/GetMyMeshDeviceItems/ZG?placeUniID=&userId="
                magichue_meshdevicesendpointnew = magichue_meshdevicesendpoint.replace("placeUniID=","placeUniID=" + placeUniID)
                magichue_meshdevicesendpointnew = magichue_meshdevicesendpointnew.replace("userId=","userId="+urllib.parse.quote_plus(self.magichue_userid))
                response = requests.get(self.magichue_connecturl + magichue_meshdevicesendpointnew, headers=headers)
                if response.status_code != 200:
                    print('Mesh device retrieval FAILED for placeUniID: ' + placeUniID + ' - ' + response.json()['error'])
                    return False
                else:
                    print('Mesh devices retrieved for placeUniID: ' + placeUniID)
                    responseJSON = response.json()['result']
                    mesh.update({'devices':responseJSON})
                    return True
        else:
            print("Login session not detected! Please login first using MagicHue_Login method.")
            return False
    
    def list_meshes(self):
        for mesh in self.magichue_meshes:
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
    
    def list_mesh_devices(self):
        for mesh in self.magichue_meshes:
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
        if command == OPCODE_STATUS_RECEIVED: #This does not return any status info, only that the device is online
            mesh_address = struct.unpack('B', data[3:4])[0]
        elif command == OPCODE_NOTIFICATION_RECEIVED:
            device_data = struct.unpack('BBBBB', data[10:15])
            mesh_address = device_data[0]
            mode = device_data[3]
            brightness = device_data[2]
            cct = color = device_data[4]
            if(mode == 63 or mode == 42):
                color_mode = 'rgb'
                rgb = ZenggeColor.decode(color) #Converts from 1 value(kelvin) to RGB
            else:
                color_mode = 'white'
                rgb = [0,0,0]
            status = {
                'type': 'notification',
                'mesh_address': mesh_address,
                'state': brightness != 0,
                'color_mode': color_mode,
                'rgb': rgb,
                'white_temperature': cct,
                'brightness': brightness,
            }
            print(f'[{self.mesh_name}][{self.mac}] Parsed status: {status}\n')
        elif command == OPCODE_RESPONSE:
            device_1_data = struct.unpack('BBBBB', data[10:15])
            device_2_data = struct.unpack('BBBBB', data[15:20])
            if (device_1_data[0] != 0):
                mesh_address = device_1_data[0]
                mode = device_1_data[3]
                brightness = device_1_data[2]
                cct = color = device_1_data[4]
                if(mode == 63 or mode == 42):
                    color_mode = 'rgb'
                    rgb = ZenggeColor.decode(color) #Converts from 1 value(kelvin) to RGB
                else:
                    color_mode = 'white'
                    rgb = [0,0,0]
                status = {
                    'type': 'status',
                    'mesh_address': mesh_address,
                    'state': brightness != 0,
                    'color_mode': color_mode,
                    'rgb': rgb,
                    'white_temperature': cct,
                    'brightness': brightness,
                }
                print(f'[{self.mesh_name}][{self.mac}] Parsed status: {status}\n')
            if (device_2_data[0] != 0):
                mesh_address = device_2_data[0]
                mode = device_2_data[3]
                brightness = device_2_data[2]
                cct = color = device_2_data[4]
                if(mode == 63 or mode == 42):
                    color_mode = 'rgb'
                    rgb = ZenggeColor.decode(color) #Converts from 1 value(kelvin) to RGB
                else:
                    color_mode = 'white'
                    rgb = [0,0,0]
                status = {
                    'type': 'notification',
                    'mesh_address': mesh_address,
                    'state': brightness != 0,
                    'color_mode': color_mode,
                    'rgb': rgb,
                    'white_temperature': cct,
                    'brightness': brightness,
                }
                print(f'[{self.mesh_name}][{self.mac}] Parsed status: {status}\n')
        else:
            print(f'[{self.mesh_name}][{self.mac}] Unknown command [{command}]')

    async def enable_notify(self): #Huge thanks to 'cocoto' for helping me figure out this issue with Zengge!!
        await self.send_packet(0x01,bytes([]),self.mesh_id,uuid=UUID_NOTIFY)
        await self.client.start_notify(UUID_NOTIFY, self.notification_handler)
        return True
    
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
            await self.enable_notify() #This will be modified later once Bleak implements a fix for start_notify issue.
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
    
    async def request_device_status(self):
        packet_data = bytes([0x01])
        await self.client.write_gatt_char(UUID_NOTIFY,packet_data)
    
    async def disconnect(self):
        self.is_connected = False
        self.sk = None
        await self.client.disconnect()
        print("Device disconnected!")


class ZenggeLight:
    def __init__(self, display_name, mac, mesh_address, device_type, mesh=None):
        self.display_name = display_name
        self.mesh_address = mesh_address
        self.mac = mac
        self.device_type = device_type
        self.control_type = None
        self.wiring_type = None
        self.ota_flag = None
        self.place_id = None
        self.mesh = mesh
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
    
    async def light_brightness(self, value=1,dimmingTarget=DIMMINGTARGET_RGBWC,delay=0,gradient=0):
        #Brightness value accepts 0-100 (0 is off) *required*
        #Dimming target specifies dimming of RGB LEDs vs White LEDs
        #Delay is in 100ms units *Default is 0-No delay* (Max value is 65535
        #Gradient is in 100ms units *Default is 0-No gradient*
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
    
    async def light_rgb(self, r=0,g=0,b=0):
        # Change mode of light (RGB, Warm, CCT/Lum, AuxLight, ColorTemp/Lum/AuxLight)
        #  0x60 is the mode for static RGB (Value1,Value2,Value3 stand for RGB values 0-255)
        #  0x61 stands for static warm white (Value1 represents warm white value 0-255)
        #  0x62 stands for color temp/luminance (Value1 represents CCT scale value 0-100, Value2 represents luminance value 0-100)
        #  0x63 stands for auxiliary light (Value1 represents aux light brightness)
        #  0x64 stands for color temp value + aux light (Value1 represents CCT ratio value 1-100, Value 2 represents luminance value 0-100, Value 3 represents aux luminance value 0-100)
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