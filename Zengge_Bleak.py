'''
The Telink encryption functions used in this project were pulled from Google's python-dimond project (NO LONGER USED)
    https://github.com/google/python-dimond
Code for changing Mesh Name and Password using factory settings was pulled from home-assistant-awox project
    https://github.com/fsaris/home-assistant-awox
'''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_str
from bleak import BleakClient,BleakScanner
from bleak.exc import BleakError
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from os import urandom
import base64
import binascii
import hashlib
import urllib
import packetutils as pckt
import requests
import json
import random
import time
import asyncio

deviceAddress_ALL = 0
deviceColorTemp = 0
deviceMode_White = 0x0
deviceMode_RGB = 0x3f
deviceMode_CCT = 0x40
opcode_SetColor = 0xe2
opcode_SetCCT = 0xf4
opcode_SetState = 0xd0
opcode_SetBrightness = 0xd0
opcode_SetFlash = 0xd2
opcode_Response = 0xdc
stateAction_Power = 0x01
stateAction_Brightness = 0x02
stateAction_IncreaseBrightness = 0x03
stateAction_DecreaseBrightness = 0x04
colorMode_RGB = 0x60
colorMode_WarmWhite = 0x61
colorMode_CCT = 0x62
colorMode_AUX = 0x63
colorMode_CCTAUX = 0x64
dimmingTarget_RGBkWC = 0x01 #Set RGB, Keep WC
dimmingTarget_WCkRGB = 0x02 #Set WC, Keep RGB
dimmingTarget_RGBWC = 0x03  #Set RGB & WC
dimmingTarget_RGBoWC = 0x04 #Set RGB, WC Off
dimmingTarget_WCoRGB = 0x05 #Set WC, RGB Off
dimmingTarget_Auto = 0x06   #Set lights according to situation
UUID_Service = "00010203-0405-0607-0809-0a0b0c0d1910"
UUID_Control = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_Notify = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_Pairing = "00010203-0405-0607-0809-0a0b0c0d1914"

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

'''
###REMOVE AFTER TESTING###
These are some old fuctions I used before discovering packetutils tool from home-assistant-awox project

def encrypt(key, data):
    k = AES.new(bytes(reversed(key)), AES.MODE_ECB)
    data = reversed(list(k.encrypt(bytes(reversed(data)))))
    rev = []
    for d in data:
        rev.append(d)
    return rev


def generate_sk(name, password, data1, data2):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    key = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    data = data1[0:8]
    data += data2[0:8]
    return encrypt(key, data)


def key_encrypt(name, password, key):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    data = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    return encrypt(key, data)


def encrypt_packet(sk, address, packet):
    auth_nonce = [address[0], address[1], address[2], address[3], 0x01, packet[0], packet[1], packet[2], 15, 0, 0, 0, 0, 0, 0, 0]
    authenticator = encrypt(sk, auth_nonce)
    for i in range(15):
      authenticator[i] = authenticator[i] ^ packet[i+5]
    mac = encrypt(sk, authenticator)
    for i in range(2):
       packet[i+3] = mac[i]
    iv = [0, address[0], address[1], address[2], address[3], 0x01, packet[0],
          packet[1], packet[2], 0, 0, 0, 0, 0, 0, 0]
    temp_buffer = encrypt(sk, iv)
    for i in range(15):
        packet[i+5] ^= temp_buffer[i]
    return packet


def decrypt_packet(sk, address, packet):
    iv = [address[0], address[1], address[2], packet[0], packet[1], packet[2], packet[3], packet[4], 0, 0, 0, 0, 0, 0, 0, 0] 
    plaintext = [0] + iv[0:15]
    result = encrypt(sk, plaintext)
    for i in range(len(packet)-7):
      packet[i+7] ^= result[i]
    return packet
'''

def GenerateTimestampCheckCode():
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


def MagicHue_SetCountryServer(countryCode=None): #{'nationName': 'United States', 'nationCode': 'US', 'serverApi': 'usmeshcloud.magichue.net:8081/MeshClouds/', 'brokerApi': 'us.meshbroker.magichue.net'}
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


def MagicHue_Login(username, password):
    global magichue_usertoken,magichue_userid,magichue_devicesecret,magichue_connecturl,magichue_userloginendpoint
    timestampcheckcode = GenerateTimestampCheckCode()
    timestamp = timestampcheckcode[0]
    checkcode = timestampcheckcode[1]
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
        responseJSON = response.json()['result']
        magichue_userid = responseJSON['userId']
        magichue_usertoken = responseJSON['auth_token']
        magichue_devicesecret = responseJSON['deviceSecret']


def MagicHue_GetMeshes():
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
            responseJSON = response.json()['result']
            magichue_meshes = responseJSON
            for mesh in magichue_meshes:
                mesh['devices'] = None
    else:
        print("Login session not detected! Please login first using MagicHue_Login method.")


def MagicHue_GetMeshDevices():
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


def MagicHue_ListMeshes():
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


def MagicHue_ListMeshDevices():
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
    def __init__(self, mac, meshID, meshName="ZenggeMesh", meshPass="ZenggeTechnology", meshLTK=None):
        #self.packet_count = random.randrange(0xffff) ###REMOVE AFTER TESTING###
        self.mac = mac
        #self.macarray = mac.split(':') ###REMOVE AFTER TESTING###
        #self.macdata = [int(self.macarray[5], 16), int(self.macarray[4], 16), int(self.macarray[3], 16), int(self.macarray[2], 16), int(self.macarray[1], 16), int(self.macarray[0], 16)] ###REMOVE AFTER TESTING###
        self.meshID = meshID
        self.meshName = meshName
        self.meshPass = meshPass
        self.meshLTK = meshLTK
        self.client = None
        self.sk = None
        self.devices = []
        self.is_connected = False
    '''
    ###REMOVE AFTER TESTING###
        async def mesh_login_OLD(self):
            if self.client == None:
                return
            data = [0] * 16
            random_data = get_random_bytes(8)
            for i in range(8):
                data[i] = random_data[i]
            enc_data = key_encrypt(self.meshName, self.meshPass, data)
            packet = [0x0c]
            packet += data[0:8]
            packet += enc_data[0:8]
            pairReply = await self.client.write_gatt_char(UUID_Pairing, bytes(packet), True)
            await asyncio.sleep(0.3)
            data2 = await self.client.read_gatt_char(UUID_Pairing)
            self.sk = generate_sk(self.meshName, self.meshPass, data[0:8], data2[1:9])
    '''
    async def mesh_login(self):
        if self.client == None:
            return
        session_random = urandom(8)
        message = pckt.make_pair_packet(self.meshName.encode(), self.meshPass.encode(), session_random)
        pairReply = await self.client.write_gatt_char(UUID_Pairing, bytes(message), True)
        await asyncio.sleep(0.3)
        reply = await self.client.read_gatt_char(UUID_Pairing)
        self.sk = pckt.make_session_key(self.meshName.encode(), self.meshPass.encode(), session_random, reply[1:9])

    '''
    ###REMOVE AFTER TESTING###
        async def send_packet_OLD(self, target, command, data):
            packet = [0] * 20
            packet[0] = self.packet_count & 0xff
            packet[1] = self.packet_count >> 8 & 0xff
            packet[5] = target & 0xff
            packet[6] = (target >> 8) & 0xff
            packet[7] = command
            packet[8] = self.meshID & 0xff
            packet[9] = (self.meshID >> 8) & 0xff
            for i in range(len(data)):
                packet[10 + i] = data[i]
            enc_packet = encrypt_packet(self.sk, self.macdata, packet)
            bytes(enc_packet)
            print(bytes(enc_packet))
            self.packet_count += 1
            if self.packet_count > 65535:
                self.packet_count = 1
            # BLE connections may not be stable. Spend up to 10 seconds trying to
            # reconnect before giving up.
            initial = time.time()
            while True:
                if time.time() - initial >= 10:
                    raise Exception("Unable to connect")
                try:
                    await self.client.write_gatt_char(UUID_Control, bytes(enc_packet))
                    break
                except:
                    self.connect()
    '''

    async def send_packet(self, command, data, dest=None, withResponse=True, attempt=0):
        """
        Args:
            command: The command, as a number.
            data: The parameters for the command, as bytes.
            dest: The destination mesh id, as a number. If None, this lightbulb's
                mesh id will be used.
        """
        assert (self.sk)
        if dest == None: dest = self.meshID
        packet = pckt.make_command_packet(self.sk, self.mac, dest, command, data)
        try:
            print(f'[{self.meshName}][{self.mac}] Writing command {command} data {repr(data)}')
            await self.client.write_gatt_char(UUID_Control, packet)
            return True
        except Exception as err:
            print(f'[{self.meshName}][{self.mac}] Command failed, attempt: {attempt} - [{type(err).__name__}] {err}')
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
        except Exception as e:
            print(f"Connection to {self.mac} failed!\nError: {e}")
            self.is_connected = False
            self.client = None
            self.sk = None
            pass
        if self.client is None or self.sk is None:
            raise Exception(f"Unable to connect to mesh {self.meshName} via {self.mac}")
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
            connect()
        message = pckt.encrypt(self.sk, new_mesh_name.encode())
        message.insert(0, 0x4)
        await self.client.write_gatt_char(UUID_Pairing, message)
        message = pckt.encrypt(self.sk, new_mesh_password.encode())
        message.insert(0, 0x5)
        await self.client.write_gatt_char(UUID_Pairing, message)
        message = pckt.encrypt(self.sk, new_mesh_long_term_key.encode())
        message.insert(0, 0x6)
        await self.client.write_gatt_char(UUID_Pairing, message)
        time.sleep(1)
        reply = bytearray(await self.client.read_gatt_char(UUID_Pairing))
        if reply[0] == 0x7:
            self.meshName = new_mesh_name
            self.meshPass = new_mesh_password
            print(f'[{self.meshName}]-[{self.meshPass}]-[{self.mac}] Mesh network settings accepted.')
            return True
        else:
            print(f'[{self.meshName}][{self.mac}] Mesh network settings change failed : {repr(reply)}')
            return False
    async def disconnect(self):
        self.is_connected = False
        self.sk = None
        await self.client.disconnect()
        print("Device disconnected!")


class ZenggeLight:
    def __init__(self, displayName, meshAddress, mac, deviceType, controlType, wiringType, otaFlag, placeID, mesh=None):
        self.displayName = displayName
        self.meshAddress = meshAddress
        self.mac = mac
        self.deviceType = deviceType
        self.controlType = controlType
        self.wiringType = wiringType
        self.otaFlag = otaFlag
        self.placeID = placeID
        self.mesh = mesh
        self.meshID = None if mesh is None else mesh.meshID
        self.state = 0
        self.brightness = 0
        self.temperature = 0
        self.red = 0
        self.green = 0
        self.blue = 0
        self.rgb = None
        self.is_connected = False
    async def check_mesh_connection(self):
        if self.mesh.is_connected is False:
            print("Mesh is not connected! Connecting...")
            await self.mesh.connect()
    async def light_on(self):
        await self.check_mesh_connection()
        packetData = bytes([self.deviceType,stateAction_Power,1])
        await self.mesh.send_packet(opcode_SetState,packetData,self.meshAddress)
        self.state = 1
    async def light_off(self):
        self.check_mesh_connection()
        packetData = bytes([self.deviceType,stateAction_Power,0])
        await self.mesh.send_packet(opcode_SetState,packetData,self.meshAddress)
        self.state = 0
    async def light_toggle(self):
        self.check_mesh_connection()
        packetData = bytes([self.deviceType,stateAction_Power,self.state^1])
        await self.mesh.send_packet(opcode_SetState,packetData,self.meshAddress)
        self.state = self.state^1
    #Brightness value accepts 0-100 (0 is off) *required*
    #Dimming target specifies dimming of RGB LEDs vs White LEDs
    #Delay is in 100ms units *Default is 0-No delay* (Max value is 65535
    #Gradient is in 100ms units *Default is 0-No gradient*
    async def light_brightness(self, value,dimmingTarget=dimmingTarget_RGBWC,delay=0,gradient=0):
        self.check_mesh_connection()
        delay0 = format(delay,'b').zfill(16)
        delayLB = int(delay0[8:16],2)
        delayHB = int(delay0[0:8],2)
        gradient0 = format(gradient,'b').zfill(16)
        gradientLB = int(gradient0[8:16],2)
        gradientHB = int(gradient0[0:8],2)
        packetData = bytes([self.deviceType,stateAction_Brightness,value,dimmingTarget,delayLB,delayHB,gradientLB,gradientHB])
        await self.mesh.send_packet(opcode_SetBrightness,packetData,self.meshAddress)
        self.brightness = value
    # Change mode of light (RGB, Warm, CCT/Lum, AuxLight, ColorTemp/Lum/AuxLight)
    #   0x60 is the mode for static RGB (Value1,Value2,Value3 stand for RGB values 0-255)
    #   0x61 stands for static warm white (Value1 represents warm white value 0-255)
    #   0x62 stands for color temp/luminance (Value1 represents CCT scale value 0-100, Value2 represents luminance value 0-100)
    #   0x63 stands for auxiliary light (Value1 represents aux light brightness)
    #   0x64 stands for color temp value + aux light (Value1 represents CCT ratio value 1-100, Value 2 represents luminance value 0-100, Value 3 represents aux luminance value 0-100)
    async def light_RGB(self, r=0,g=0,b=0):
        self.check_mesh_connection()
        packetData = bytes([self.deviceType,colorMode_RGB,r,g,b])
        await self.mesh.send_packet(opcode_SetColor,packetData,self.meshAddress)
        self.r = r
        self.g = g
        self.b = b
        self.rgb = True
    async def light_WarmWhite(self, LUM):
        self.check_mesh_connection()
        packetData = bytes([self.deviceType,colorMode_WarmWhite,LUM])
        await self.mesh.send_packet(opcode_SetColor,packetData,self.meshAddress)
        self.temperature = LUM
        self.rgb = False
    async def light_CCT(self, CCT,LUM):
        self.check_mesh_connection()
        packetData = bytes([self.deviceType,colorMode_CCT,CCT,LUM])
        await self.mesh.send_packet(opcode_SetColor,packetData,self.meshAddress)
        self.temperature = CCT
        self.brightness = LUM
        self.rgb = False