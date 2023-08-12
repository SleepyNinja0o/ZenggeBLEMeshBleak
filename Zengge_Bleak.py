#The Telink encryption functions used in this project were pulled from Google's python-dimond project here:  https://github.com/google/python-dimond. Many thanks to mjg59!

from bleak import BleakClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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


class ZenggeMesh:
    def __init__(self, vendor, mac, meshName, meshPass):
        self.packet_count = random.randrange(0xffff)
        self.mac = mac
        self.macarray = mac.split(':')
        self.macdata = [int(self.macarray[5], 16), int(self.macarray[4], 16), int(self.macarray[3], 16), int(self.macarray[2], 16), int(self.macarray[1], 16), int(self.macarray[0], 16)]
        self.vendor = vendor
        self.meshName = meshName
        self.meshPass = meshPass
        self.client = None
        self.sk = None
        self.devices = []
        self.is_connected = False
    async def mesh_login(self):
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
    async def send_packet(self, target, command, data):
        packet = [0] * 20
        packet[0] = self.packet_count & 0xff
        packet[1] = self.packet_count >> 8 & 0xff
        packet[5] = target & 0xff
        packet[6] = (target >> 8) & 0xff
        packet[7] = command
        packet[8] = self.vendor & 0xff
        packet[9] = (self.vendor >> 8) & 0xff
        for i in range(len(data)):
            packet[10 + i] = data[i]
        enc_packet = encrypt_packet(self.sk, self.macdata, packet)
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
    async def connect(self):
        try:
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
    async def disconnect(self):
        self.is_connected = False
        self.sk = None
        await self.client.disconnect()
        print("Device disconnected!")


class ZenggeLight:
    def __init__(self, name, id, mac, type, mesh=None):
        self.mesh = mesh
        self.name = name
        self.id = id
        self.mac = mac
        self.type = type
        self.state = 0
        self.brightness = 0
        self.temperature = 0
        self.red = 0
        self.green = 0
        self.blue = 0
        self.rgb = None
        self.is_connected = False
    async def connect(self):
        await self.mesh.connect()
        self.is_connected = True
    async def light_on(self):
        packetData = [self.type,stateAction_Power,1]
        await self.mesh.send_packet(self.id,opcode_SetState,packetData)
        self.state = 1
    async def light_off(self):
        packetData = [self.type,stateAction_Power,0]
        await self.mesh.send_packet(self.id,opcode_SetState,packetData)
        self.state = 0
    async def light_toggle(self):
        packetData = [self.type,stateAction_Power,self.state^1]
        await self.mesh.send_packet(self.id,opcode_SetState,packetData)
        self.state = self.state^1
    #Brightness value accepts 0-100 (0 is off) *required*
    #Dimming target specifies dimming of RGB LEDs vs White LEDs
    #Delay is in 100ms units *Default is 0-No delay* (Max value is 65535
    #Gradient is in 100ms units *Default is 0-No gradient*
    async def light_brightness(self, value,dimmingTarget=dimmingTarget_RGBWC,delay=0,gradient=0):
        delay0 = format(delay,'b').zfill(16)
        delayLB = int(delay0[8:16],2)
        delayHB = int(delay0[0:8],2)
        gradient0 = format(gradient,'b').zfill(16)
        gradientLB = int(gradient0[8:16],2)
        gradientHB = int(gradient0[0:8],2)
        packetData = [self.type,stateAction_Brightness,value,dimmingTarget,delayLB,delayHB,gradientLB,gradientHB]
        await self.mesh.send_packet(self.id,opcode_SetBrightness,packetData)
        self.brightness = value
    # Change mode of light (RGB, Warm, CCT/Lum, AuxLight, ColorTemp/Lum/AuxLight)
    #   0x60 is the mode for static RGB (Value1,Value2,Value3 stand for RGB values 0-255)
    #   0x61 stands for static warm white (Value1 represents warm white value 0-255)
    #   0x62 stands for color temp/luminance (Value1 represents CCT scale value 0-100, Value2 represents luminance value 0-100)
    #   0x63 stands for auxiliary light (Value1 represents aux light brightness)
    #   0x64 stands for color temp value + aux light (Value1 represents CCT ratio value 1-100, Value 2 represents luminance value 0-100, Value 3 represents aux luminance value 0-100)
    async def light_RGB(self, r=0,g=0,b=0):
        packetData = [self.type,colorMode_RGB,r,g,b]
        await self.mesh.send_packet(self.id,opcode_SetColor,packetData)
        self.r = r
        self.g = g
        self.b = b
        self.rgb = True
    async def light_WarmWhite(self, LUM):
        packetData = [self.type,colorMode_WarmWhite,LUM]
        await self.mesh.send_packet(self.id,opcode_SetColor,packetData)
        self.temperature = LUM
        self.rgb = False
    async def light_CCT(self, CCT,LUM):
        packetData = [self.type,colorMode_CCT,CCT,LUM]
        await self.mesh.send_packet(self.id,opcode_SetColor,packetData)
        self.temperature = CCT
        self.brightness = LUM
        self.rgb = False
