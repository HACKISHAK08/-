#سورس بوت كلان ZIX OFFICIAL 
#كسم كل واحد كلاوي و يغير في المعلومات 
import threading
import jwt
#________________________________
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
#________________________________
import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
#________________________________
import logging
import re
import socket
#________________________________
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
#________________________________
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
#________________________________
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*
#DEV ZIX OFFICIAL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
paylod_token1 = "1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5055"
freefire_version = "ob50"
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "98.98.162.80"
chat_port = 39698
key2 = "ZIX"
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#DEV ZIX OFFICIAL V8

#________________________________
B = '''[1;30m'''
R = '''[1;31m'''
G = '''[1;32m'''
Y = '''[1;33m'''
Bl = '''[1;34m'''
P = '''[1;35m'''
Z = '''[1;36m'''
W = '''[1;37m'''
from flask import Flask
import random
app = Flask(__name__)
global_client = None  # سيتم تعيينه عند تشغيل العميل
from flask import Flask, jsonify
  # سيتم تعيينه عند تشغيل العميل
@app.route('/')
def health_check():
    return "Server Ready", 200
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#________________________________
class LagThread(threading.Thread):
    def __init__(self, socket_client, team_code, repeat_count, key, iv, uid):
        threading.Thread.__init__(self)
        self.socket_client = socket_client
        self.team_code = team_code
        self.repeat_count = repeat_count
        self.key = key
        self.iv = iv
        self.uid = uid
        self.running = True
        
    def run(self):
        try:
            for i in range(self.repeat_count):
                if not self.running:
                    break
                    
                for _ in range(1111):
                    if not self.running:
                        break
                        
                    join_teamcode(self.socket_client, self.team_code, self.key, self.iv)
                    time.sleep(0)
                    
                    leave_packet = self.create_leave_packet()
                    self.socket_client.send(leave_packet)
                    time.sleep(0)
                    
        except Exception as e:
            print(f"Error in LagThread: {e}")
            
    def create_leave_packet(self):
        fields = {
            1: 7,
            2: {
                1: 11371687918
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + encrypt_packet(packet, self.key, self.iv)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + encrypt_packet(packet, self.key, self.iv)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + encrypt_packet(packet, self.key, self.iv)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + encrypt_packet(packet, self.key, self.iv)
            
        return bytes.fromhex(final_packet)
        
    def stop(self):
        self.running = False

def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']

def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
def talk_with_ai(question):
    url = f"https://princeaiapi.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "حدث خطأ أثناء الاتصال بالخادم."
        
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom

def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader

def generate_random_color():
    color_list = [
        "[00FF00][b][c]",
        "[FFDD00][b][c]",
        "[3815F3][b][c]",
        "[FF0000][b][c]",
        "[0000FF][b][c]",
        "[FFA500][b][c]",
        "[DF07F8][b][c]",
        "[1996FD][b][c]",
        "[DCE775][b][c]",
        "[A8E6CF][b][c]",
        "[7CB342][b][c]",
        "[FF0000][b][c]",
        "[FFB300][b][c]",
        "[90EE90][b][c]"
    ]
    random_color = random.choice(color_list)
    return random_color
#صدقت انه بدون ملف بايت ما بشتغل 
def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed

def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


    return message        

def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number

def newinfo(uid):
    try:
        url = f"https://zix-official-info-ob50.vercel.app/get?uid={uid}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(f"Response Data: {data}")

            if "basicinfo" in data and isinstance(data["basicinfo"], list) and len(data["basicinfo"]) > 0:
                data["basic_info"] = data["basicinfo"][0]
            else:
                print("Error: 'basicinfo' key not found or empty")
                return {"status": "wrong_id"}

            if "claninfo" in data and isinstance(data["claninfo"], list) and len(data["claninfo"]) > 0:
                data["clan_info"] = data["claninfo"][0]
            else:
                data["clan_info"] = "false"

            if "clanadmin" in data and isinstance(data["clanadmin"], list) and len(data["clanadmin"]) > 0:
                data["clan_admin"] = data["clanadmin"][0]
            else:
                data["clan_admin"] = "false"

            return {"status": "ok", "info": data}

        elif response.status_code == 500:
            print("Server Error: 500 - Internal Server Error")
            return {"status": "error", "message": "Server error, please try again later."}

        print(f"Error: Unexpected status code {response.status_code}")
        return {"status": "wrong_id"}

    except Exception as e:
        print(f"Error in newinfo: {str(e)}")
        return {"status": "error", "message": str(e)}
	
def send_spam(uid):
    try:
        info_response = newinfo(uid)
        
        if info_response.get('status') != "ok":
            return (
                f"[FF0000]-----------------------------------\n"
                f"خطأ في المعرف: {fix_num(uid)}\n"
                f"الرجاء التحقق من الرقم\n"
                f"-----------------------------------\n"
            )
        
        api_url = f"https://zix-official-spam-friend.vercel.app/SPM?uid={uid}"
        response = requests.get(api_url)
        
        if response.status_code == 200:
            return (
                f"{generate_random_color()}-----------------------------------\n"
                f"تم إرسال طلب صداقة بنجاح ✅\n"
                f"إلى: {fix_num(uid)}\n"
                f"-----------------------------------\n"
            )
        else:
            return (
                f"[FF0000]-----------------------------------\n"
                f"فشل الإرسال (كود الخطأ: {response.status_code})\n"
                f"-----------------------------------\n"
            )
            
    except requests.exceptions.RequestException as e:
        return (
            f"[FF0000]-----------------------------------\n"
            f"فشل الاتصال بالخادم:\n"
            f"{str(e)}\n"
            f"-----------------------------------\n"
        )

def send_likes(uid):
    likes_api_response = requests.get(f"https://zix-official-likes-ccta.vercel.app/like?uid={uid}")
    
    if likes_api_response.status_code == 200:
        api_data = likes_api_response.json()

        message_text = api_data.get("message", "").lower()
        status = api_data.get("status", "").lower()

        if "لم تُحتسب" in message_text or "limit" in message_text or status == "warning":
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ Daily like limit reached!\n"
                    f" Try again after 24 hours\n"
                    f"________________________"
                )
            }
        else:
            return {
                "status": "ok",
                "message": (
                    f"[C][B][00FF00]________________________\n"
                    f" ✅ Likes sent successfully!\n"
                    f" Previous Likes: {api_data.get('likes_before', 'N/A')}\n"
                    f" New Likes: {api_data.get('likes_after', 'N/A')}\n"
                    f" Likes Added: {api_data.get('likes_added', 'N/A')}\n"
                    f"________________________"
                )
            }
    else:
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ Failed to send!\n"
                f" Check the user ID\n"
                f"________________________"
            )
        }
        

		
def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80

        encoded_bytes.append(byte)
        if not number:
            break

    return bytes(encoded_bytes).hex()
def get_random_avatar():
	avatar_list = ['902033020']
	random_avatar = random.choice(avatar_list)
	return  random_avatar
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.lag_thread = None
        self.get_tok()



    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")



    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "[ff0006]ZIX OFFICIAL",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "ME",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11371687918
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "ME",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)                
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11371687918,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)     
           
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "ZIX OFFICIAL",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def info_room(self, idrooom):
        fields = {
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)




    def GenResponsMsg(self, Msg):
        fields = {
        1: 1,
        2: {
            1: 12194779602,#bot account id
            2: 3082574840,#clan id
            3: 1,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
            1: "fo",
            2: int(get_random_avatar()),
            4: 330,
            8: "OK",
            10: 1,
            11: 1
            },
            10: "en",
            13: {
            1: "https://lh3.googleusercontent.com/a/ACg8ocLP5THAwyZc0VmDXVRiNyKPxGYnALBU4bfb9OzVMHvI_t3YioI=s96-c",
            2: 1,
            3: 1
            },
            14: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

        
                
                        
                                
                                                
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "wW_T",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

        
                
                                
    def joinclanchat(self):
        fields = {
            1: 3,
            2: {
                1: 3082574840,#clan id
                2: 1,
                4: str("DvX0uvHXMazcwede4dj2jQ"),#clan key
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)




    def joinclanchat1(self):
        fields = {
        1: 3,
        2: {
            2: 5,
            3: "en"
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)

        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4] and len(data2.hex()) > 30:
                if sent_inv == True:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    print(accept_packet)
                    print(tempid)
                    aa = gethashteam(accept_packet)
                    ownerid = getownteam(accept_packet)
                    print(ownerid)
                    print(aa)
                    ss = self.accept_sq(aa, tempid, int(ownerid))
                    socket_client.send(ss)
                    sleep(1)
                    startauto = self.start_autooo()
                    socket_client.send(startauto)
                    start_par = False
                    sent_inv = False
            if data2 == b"":                
                print("Connection closed by remote host")
#                restart_program()

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "-OFFLINE":
                        tempdata = f"-THE ID IS {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"-ID : {idplayer1}\nstatus : {tempdata}\n-ID ROOM : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}\n-LEADEER ID : {idleader1}"
                        else:
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                    print(tempdata1)
                    
    def start_spam(self, player_id):
        self.spam_active = True
        def spam_loop():
            while self.spam_active:
                try:
                    invskwad = self.request_skwad(player_id)
                    socket_client.send(invskwad)
                    time.sleep(0.5)
                except Exception as e:
                    print(f"Error in spam thread: {e}")
                    break
        
        spam_thread = Thread(target=spam_loop)
        spam_thread.daemon = True
        spam_thread.start()

    def stop_spam(self):
        self.spam_active = False

    def start_room_spam(self, room_id, player_id):
        self.room_spam_active = True
        def room_spam_loop():
            packetspam = self.spam_room(room_id, player_id)
            while self.room_spam_active:
                try:
                    socket_client.send(packetspam)
                    time.sleep(0.9)
                except Exception as e:
                    print(f"Error in room spam thread: {e}")
                    break
        
        room_thread = Thread(target=room_spam_loop)
        room_thread.daemon = True
        room_thread.start()

    def stop_room_spam(self):
        self.room_spam_active = False

    def handle_spam_command(self, data):
        try:
            command_split = re.split("/spam", str(data))
            if len(command_split) > 1:
                player_id = command_split[1].split('(')[0].strip()
                if "***" in player_id:
                    player_id = player_id.replace("***", "106")

                print(f"Starting spam for player: {player_id}")
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                
                self.start_spam(player_id)
                
                clients.send(
                    self.GenResponsMsg(
                        f"{generate_random_color()}تم بدء سبام الإنضمام للاعب {fix_num(player_id)}",
                        uid))

        except Exception as e:
            print(f"Error in /spam command: {e}")

    def handle_room_command(self, data):
        try:
            command_split = re.split("/room", str(data))
            if len(command_split) > 1:
                player_id = command_split[1].split('(')[0].strip()
                if "***" in player_id:
                    player_id = player_id.replace("***", "106")

                print(f"Checking player room status: {player_id}")
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                
                packetmaker = self.createpacketinfo(player_id)
                socket_client.send(packetmaker)
                time.sleep(1)
                
                if "IN ROOM" in tempdata:
                    room_id = get_idroom_by_idplayer(data22)
                    self.start_room_spam(room_id, player_id)
                    
                    clients.send(
                        self.GenResponsMsg(
                            f"{generate_random_color()}تم بدء سبام الروم للاعب {fix_num(player_id)}",
                            uid))
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"{generate_random_color()}اللاعب ليس في روم حالياً",
                            uid))

        except Exception as e:
            print(f"Error in /room command: {e}")                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")

    def join_room_chanel(self, room_id, room_code):
        key, iv = self.key, self.iv
        fields = {
            1: 3,
            2: {
                1: int(room_id),
                2: 3,
                3: "ar",
                4: room_code, 
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
                    
    def request_skwad(self, idplayer):
        print(R)
        
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "ME",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: 902033020,
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        
        print(bytes.fromhex(final_packet))
        return bytes.fromhex(final_packet)
    def comudnity(packet_int):
        
        def send_packet():
            
            socket_client.send(packet_int)
            print("Succesfully")
        
        threads = []
        for _ in range(40):
            import time
            time.sleep(0.10)
            thread = threading.Thread(target=send_packet)
            thread.start()
            threads.append(thread)                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
#━━━━━━━━━━━━━━━━━━━
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, chat_ip, chat_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()        
        clients.send(self.joinclanchat())
        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")
            
            if senthi == True:
                
                clients.send(
                        self.GenResponsMsg(
                            f"""[C][B]السلام عليكم كيف حالك شكرا على قبول طلب صداقة ارسل ايموجي لمعرفة ما عليك فعله""", idinv
                        )
                )
                senthi = False            
            if "1200" in data.hex()[0:4]:               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"""[b][c][ffd319]Ⓥ[00FF00] [00FF00][c][b]🌟 Welcome to bot isso🌟

[DA70D6]━━━━━━━━━━━━━
[FFD54F]✨ أهلًا بك! أنا في خدمتك ✨

[000FFF][c]لاكتشاف قائمة الأوامر الخاصة بي،
[c]من فضلك، أرسل الأمر التالي:

[00FF00][b][c]/🤔help[/b]


[DA70D6]━━━━━━━━━━━━━

[FF6F61]i[FF8A65]s[FFB74D]h[FFD54F]a[FFF176]k[AED581] [81C784]i[4DB6AC]s[4FC3F7]s[7986CB]o [BA68C8]

[00CED1]

[b][c][ffd319]Ⓥ[00FF00]telegram[FFD54F]: @ishakspeed

[b][c][ffd319]Ⓥ[00FF00] instagram[FFD54F]: ishak_ishak.26
"""
                            )
                        )
                else:
                    pass
####################################
            #SEND SKWAD 5 TO ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/5 " in data:
                try:
                    message = data.decode('utf-8', errors='ignore')
                    unwanted_chars = ["(J,", "(J@", "(", ")", "@", ","]
                    cleaned_message = message
                    for char in unwanted_chars:
                        cleaned_message = cleaned_message.replace(char, "")
                    
                    try:
                        message_parts = cleaned_message.split()
                        iddd = None
                        for part in message_parts:
                            if '//5 ' in part:
                                digits = ''.join(filter(str.isdigit, part.split('/5 ')[1]))
                                if digits:
                                    iddd = int(digits)
                                    break
                        if iddd is None:
                            iddd = 10414593349
                    except:
                        iddd = 10414593349
                    
                    packetfinal = self.changes(4)
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)
                        socket_client.send(packetfinal)
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        iddd = fix_num(iddd)
                        clients.send(self.GenResponsMsg(f"""
                [11EAFD][b][c]
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                تم فتح سكواد 5 الى الاعب : 
                {iddd}
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                [FFB300][b][c]BOT MADE BY ZIX OFFICIAL 
                """))
                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                except Exception as e:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(self.GenResponsMsg("[FF0000][b]❗ حدث خطأ في العملية[/b]",uid))
                    except:
                        restart_program()
####################################
            #MAKE SKWAD 3 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/3s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                sender_id = parsed_data["5"]["data"]["1"]["data"]
                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                if True:

                
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)             
                    sleep(1)
                    packetfinal = self.changes(2)
                    iddd=parsed_data["5"]["data"]["1"]["data"]
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    if iddd:
    	                clients.send(
    	                    self.GenResponsMsg(
    	                        f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    إقبل طلب بسرعة!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY TEAM
    	                        """
    	                    )
    	                )
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)   
            #MAKE SKWAD 4 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/4s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                sender_id = parsed_data["5"]["data"]["1"]["data"]
                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                if True:
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)             
                    sleep(1)
                    packetfinal = self.changes(3)
                    iddd=parsed_data["5"]["data"]["1"]["data"]
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    if iddd:
    	                clients.send(
    	                    self.GenResponsMsg(
    	                        f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    إقبل طلب بسرعة!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY ZIX OFFICIAL TEAM
    	                        """
    	                    )
    	                )
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee) 
            #MAKE SKWAD 5 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/5s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                sender_id = parsed_data["5"]["data"]["1"]["data"]
                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                if True:
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)             
                    sleep(1)
                    packetfinal = self.changes(4)
                    iddd=parsed_data["5"]["data"]["1"]["data"]
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    if iddd:
    	                clients.send(
    	                    self.GenResponsMsg(
    	                        f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    إقبل طلب بسرعة!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY ZIX OFFICIAL 
    	                        """
    	                    )
    	                )
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)       	                
                # التأكد من المغادرة بعد 5 ثوانٍ إذا لم تتم المغادرة تلقائيًا
                sleep(5)
                print("Checking if still in squad...")

                leavee = self.leave_s()
                socket_client.send(leavee)

                 # تأخير أطول للتأكد من تنفيذ المغادرة قبل تغيير الوضع
                sleep(5)

                 # إرسال أمر تغيير وضع اللعبة إلى Solo
                change_to_solo = self.changes(1)  # تأكد أن `1` هو القيمة الصحيحة لـ Solo
                socket_client.send(change_to_solo)

                 # تأخير بسيط قبل إرسال التأكيد للمستخدم
                sleep(2)

                clients.send(
                     self.GenResponsMsg(
                         f"[C][B] [FF00FF]Successfully left squad! Now in Solo mode.", uid
                     )
                 ) 

            if "1200" in data.hex()[0:4] and b"/6s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                sender_id = parsed_data["5"]["data"]["1"]["data"]
                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                if True:
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)             
                    sleep(1)
                    packetfinal = self.changes(5)
                    iddd=parsed_data["5"]["data"]["1"]["data"]
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    if iddd:
    	                clients.send(
    	                    self.GenResponsMsg(
    	                        f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    إقبل طلب بسرعة!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY ZIX OFFICIAL TEAM
    	                        """
    	                    )
    	                )                    	                                    	                
####################################
            # GET PLAYER COMMAND
            if "1200" in data.hex()[0:4] and b"/inv " in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    iddd = default_id
                    
                    try:
                        import re
                        # البحث عن نمط /inv/ متبوعًا بأرقام
                        id_match = re.search(r'/inv (\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = id_match.group(1)
                             
                            if not (5 <= len(iddd) <= 15) or not iddd.isdigit():
                                iddd = default_id
                        else:
                             
                            temp_id = cleaned_message.split('/inv/')[1].split()[0].strip()
                            iddd = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                        
                        # معالجة الرموز الخاصة
                        iddd = iddd.replace("***", "106") if "***" in iddd else iddd
                        
                    except Exception as e:
                        print(f"Player ID extraction error: {e}")
                        iddd = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        numsc = 5
                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)
                        packetfinal = self.changes(numsc)
                        socket_client.send(packetfinal)
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
                        invitessa = self.invite_skwad(uid)
                        socket_client.send(invitessa)
                        
                        clients.send(self.GenResponsMsg(f"""
                [11EAFD][b][c]
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                إقبل طلب بسرعة!!!
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                [FFB300][b][c]BOT MADE BY ZIX OFFICIAL
                """))
                        
                        sleep(9)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Get Player Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "ID" in str(e) else f"[FF0000]خطأ في جلب اللاعب: {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()

            # SPAM JOIN SKWAD COMMAND
            if "1200" in data.hex()[0:4] and b"/sm " in data:
                try:                
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    default_id = 10414593349
                    iddd = default_id
                    try:
                        import re
                        
                        id_match = re.search(r'/sm (\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = int(id_match.group(1))
                            
                            if not (5 <= len(str(iddd)) <= 15):
                                iddd = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/sm ')[1].split()[0].strip()
                            iddd = int(temp_id) if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Spam ID extraction error: {e}")
                        iddd = default_id
                    json_result = get_available_room(data.hex()[10:])
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        invskwad = self.request_skwad(iddd)
                        socket_client.send(invskwad)
                        parsed_data = json.loads(json_result)
                        for _ in range(30):
                            socket_client.send(invskwad)
                        
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        iddd_display = fix_num(iddd)
                        clients.send(self.GenResponsMsg(f"""
                [11EAFD][b][c]
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                تم بدأ السبام طلبات إنضمام للاعب:
                {iddd_display}
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                [FFB300][b][c]BOT MADE BY ZIX OFFICIAL 
                """))
                        
                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Spam Command Error: {e}")
                    restart_program()
            # PLAYER STATUS COMMAND
            if "1200" in data.hex()[0:4] and b"/status " in data:
                try:
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    player_id = default_id
                    
                    try:
                        
                        import re
                        id_match = re.search(r'/status (\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                            
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/status ')[1].split()[0].strip()
                           
                            temp_id = temp_id.replace("***", "106") if "***" in temp_id else temp_id
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as extract_error:
                        print(f"ID extraction error: {extract_error}")
                        player_id = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        sleep(1)                
                        if statusinfo:
                            status_msg = f"[b][C][00FFFF]{tempdata}"
                            clients.send(self.GenResponsMsg(status_msg))
                        
                except Exception as e:
                    print(f"Player Status Command Error: {e}")
                    try:
                        
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error processing status request"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()

####################################
            #CHECK ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/check " in data:
                try:
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
                    import re
                    id_match = re.search(r'/check (\d{5,15})\b', cleaned_message)                    
                    if not id_match:
                        id_match = re.search(r'/check ([0-9]+)', cleaned_message)                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("Invalid ID length (5-15 digits required)")
                    else:
                        raise ValueError("No valid player ID found in message")
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        clients.send(self.GenResponsMsg("Okay Sir, Please Wait.."))
                        banned_status = check_banned_status(player_id)
                        player_id = fix_num(player_id)
                        status = banned_status['status']
                        response_message = f"""
                [11EAFD][b][c]
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                Player Name: {banned_status['player_name']}
                Player ID : {player_id}
                Status: {status}
                °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
                [FFB300][b][c]BOT
                """
                        clients.send(self.GenResponsMsg(response_message))
                except Exception as e:
                    print(f"\nProcessing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: Failed to process command - {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()
####################################
            #GET ID REGION ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/region " in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
            
                    # استخراج ID باستخدام regex
                    import re
                    id_match = re.search(r'/region (\d{5,15})\b', cleaned_message)
                    
                    if not id_match:
                        # محاولة بديلة إذا فشلت الأولى
                        id_match = re.search(r'/region (\d+)', cleaned_message)
                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        
                        # التحقق من طول ID
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("يجب أن يكون طول الآيدي بين 5-15 رقم")
                    else:
                        raise ValueError("لم يتم العثور على آيدي لاعب صالح في الرسالة")
            
                    # المتابعة مع باقي العمليات
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        clients.send(self.GenResponsMsg("جاري المعالجة..."))
                        
                        b = get_player_info(player_id)
                        player_id = fix_num(player_id)
                        response_message = f"""
                [11EAFD][b][c]تم إرسال طلب الصد
                """
                        clients.send(self.GenResponsMsg(response_message))
            
                except Exception as e:
                    print(f"\nError: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "آيدي" in str(e) else f"[FF0000]خطأ في المعالجة: {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()

            
                except Exception as e:
                    print(f"\nProcessing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {str(e)}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()
            # AI COMMAND

            
                                    

                                  

            
            if "1200" in data.hex()[0:4] and b"/ai" in data:
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        clients.send(self.GenResponsMsg("جاري جلب الإتصال بذكاء..."))
                        
                        # استخراج السؤال بطريقة أكثر قوة
                        try:
                            raw_message = data.decode('utf-8', errors='ignore').replace('\x00', '')
                            question_part = raw_message.split('/ai')[1]
                            
                            # تنظيف السؤال من الرموز غير المرغوبة
                            unwanted_chars = ["***", "\\x", "\x00"]
                            cleaned_question = question_part
                            for char in unwanted_chars:
                                cleaned_question = cleaned_question.replace(char, "")
                                
                            question = cleaned_question.strip()
                            if not question:
                                raise ValueError("No question provided")
                                
                            # استبدال *** بقيمة افتراضية
                            question = question.replace("***", "106") if "***" in question else question
                            
                            ai_msg = talk_with_ai(question)
                            clients.send(self.GenResponsMsg(ai_msg))
                        except Exception as ai_error:
                            print(f"AI Processing Error: {ai_error}")
                            restart_program()
            
                except Exception as e:
                    print(f"AI Command Error: {e}")
                    restart_program()

            # CLAN INFO COMMAND
            if "1200" in data.hex()[0:4] and b"/clan " in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    # استخراج Clan ID بنظام متقدم
                    default_clan_id = "3080179038"
                    clan_id = default_clan_id  # القيمة الافتراضية
                    
                    try:
                        import re
                        # المحاولة الأولى: البحث عن نمط /clan/ متبوعًا بأرقام
                        id_match = re.search(r'/clan (\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            clan_id = id_match.group(1)
                            print(f"Extracted Clan ID: {clan_id}")
                            
                            # التحقق من صحة الآيدي
                            if not (5 <= len(clan_id) <= 15) or not clan_id.isdigit():
                                print("Invalid Clan ID format, using default")
                                clan_id = default_clan_id
                        else:
                            # المحاولة الثانية: طريقة بديلة إذا فشلت الأولى
                            parts = cleaned_message.split('/clan ')
                            if len(parts) > 1:
                                temp_id = parts[1].split()[0].strip()
                                if temp_id.isdigit() and 5 <= len(temp_id) <= 15:
                                    clan_id = temp_id
                                else:
                                    print("Invalid Clan ID in fallback method, using default")
                                    clan_id = default_clan_id
                            else:
                                print("No Clan ID found, using default")
                                clan_id = default_clan_id
                                
                    except Exception as extract_error:
                        print(f"Clan ID extraction error: {extract_error}, using default")
                        clan_id = default_clan_id
            
                    # المتابعة مع باقي العمليات
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
                        clients.send(self.GenResponsMsg("جاري جلب معلومات كلان..."))
                        
                        clan_info = Get_clan_info(clan_id)
                        clan_id = fix_num(clan_id)
                        clients.send(self.GenResponsMsg(clan_info))
            
                except Exception as e:
                    print(f"\nClan Processing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {str(e)}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()
####################################
            if "1200" in data.hex()[0:4] and b"/room " in data:
                	import re
                	i = re.split("/room ", str(data))[1] 
                	sid = str(i).split("(\\x")[0]
                	json_result = get_available_room(data.hex()[10:])
                	parsed_data = json.loads(json_result)
                	sender_id = parsed_data["5"]["data"]["1"]["data"]
                	sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                	if True:
                        	uid = parsed_data["5"]["data"]["1"]["data"]
                        	split_data = re.split(rb'/room ', data)
                        	room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        	if room_data and len(room_data) > 0:
                            		player_id = room_data[0]
                            
                            		if not any(char.isdigit() for char in player_id):
                            			clients.send(self.GenResponsMsg(f"[C][B][ff0000] - Error! "))
                            		else:
                            			player_id = room_data[0]
                            		if player_id.isdigit():
                                		if "***" in player_id:
                                    			player_id = rrrrrrrrrrrrrr(player_id)                        			
                                		packetmaker = self.createpacketinfo(player_id)
                                		socket_client.send(packetmaker)
                                		sleep(0.5)
                                		if "IN ROOM" in tempdata:
                                    			room_id = get_idroom_by_idplayer(data22)
                                    			packetspam = self.spam_room(room_id, player_id)
                                    			print(packetspam.hex())
                                    			clients.send(
                                        self.GenResponsMsg(
                                            f"\n{generate_random_color()}- SpAm StArtEd For uid {fix_num(player_id)} !\n"
                                        )
                                    )
                                    
                                    
                                    			for _ in range(10):
        #                                sleep(0.5)
                                        			packetspam = self.spam_room(room_id, player_id)
        
                                        			print(" sending spam to "+player_id)
                                        			threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                                    			clients.send(
                                        self.GenResponsMsg(
                                            f"\n\n\n{generate_random_color()} [00FF00]Successfully Spam SeNt !\n\n\n"
                                        )
                                    )
                                		else:
                                		      clients.send(
                                        self.GenResponsMsg(
                                            f"\n\n\n[C][B] [FF00FF]The player is not in room\n\n\n"
                                        )
                                    )      
                            		else:
                            		      clients.send(
                                    self.GenResponsMsg(
                                        f"\n\n\n[C][B] [FF00FF]Please write the id of player not!\n\n\n"
                                    )
                                )   
                        	else:
                        	       clients.send(
                                self.GenResponsMsg(
                                    f"\n\n\n[C][B] [FF00FF]Please write the id of player !\n\n\n"
                                )
                            )                          
####################################
            if "1200" in data.hex()[0:4] and b"/info " in data:
                  import re
                  command_split = re.split("/info ", str(data))
                  if len(command_split) > 1:
                      json_result = get_available_room(data.hex()[10:])
                      parsed_data = json.loads(json_result)
                      sender_id = parsed_data["5"]["data"]["1"]["data"]
                      sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                      if True:
                          uid = command_split[1].split("\\x")[0].strip()
                          uid = command_split[1].split('(')[0].strip()
                          info_response = newinfo(uid)
                          uid = uid + 'َKKKKKKKKKKKKK'
                          infoo = info_response['info']
                          basic_info = infoo['basic_info']
                          clan_info = infoo['clan_info']
                          clan_admin = infoo['clan_admin']
                          print(clan_info)
                          if clan_info == "false":
                          	clan_info = "\nPlayer Not In Clan\n"
                          else:
                          	clan_id = clan_info['clanid']
                          	clan_name = clan_info['clanname']
                          	clan_level = clan_info['guildlevel']
                          	clan_members = clan_info['livemember']
                          	clan_admin_name = clan_admin['adminname']
                          	clan_admin_brrank = clan_admin['brpoint']
                          	clan_admin_exp = clan_admin['exp']
                          	clan_admin_id = fix_num(clan_admin['idadmin'])
                          	clan_admin_level = clan_admin['level']
                          	clan_info = (	                        f" Clan Info :\n"
                          	f"Clan ID : {fix_num(clan_id)}\n"
                               f"Clan Name :  {clan_name}\n"
                              f"Clan Level: {clan_level}\n\n"
                              "Clan Admin Info:: \n"
                              f"ID : {clan_admin_id}\n"
                              f"Name : {clan_admin_name}\n"
                              f"Exp : {clan_admin_exp}\n"
                              f"Level : {clan_admin_level}\n"
                              f"Ranked (Br) Score : {clan_admin_brrank}\n"
                              )
                          
                          if info_response['status'] == "ok":
                           level = basic_info['level']
                           likes = basic_info['likes']
                           name = basic_info['username']
                           region = basic_info['region']
                           bio = basic_info['bio']
                           if "|" in bio:
                           	bio = bio.replace("|"," ")
                           br_rank = fix_num(basic_info['brrankscore'])
                           exp = fix_num(basic_info['Exp'])
                           print(level,likes,name,region)
                           message_info = (	                    
                              f"[C][FFB300] Basic Account info :\n"
                              f"Server : {region}\n"
                              f"Name : {name}\n"
                              f"Bio : {bio}\n"
                              f"Level : {level}\n"
                              f"Exp : {exp}\n"
                              
                              f"Likes : {fix_num(likes)}\n"
                              f"Ranked (Br) Score : {br_rank}"
                              
        
        f"{clan_info}\n"
        f"[FF0000]Command Sent By : {sender_name}\n"
        f"Command Sender Id : {fix_num(sender_id)}\n\n"
        
                              
        
                              )
                          else:
                          	message_info = (f"[C][B] [FF0000]-----------------------------------\n"
                              f" Wrong ID ..\n"
                               f" Please Check Again\n"
                              
                              f"-----------------------------------")
                          
                          json_result = get_available_room(data.hex()[10:])
                          parsed_data = json.loads(json_result)
                          uid = parsed_data["5"]["data"]["1"]["data"]
                          clients.send(
                          self.GenResponsMsg(
                              f"{generate_random_color()}Okay Sir, Please Wait.."
                          )
                      )
                          json_result = get_available_room(data.hex()[10:])
                          parsed_data = json.loads(json_result)
                          uid = parsed_data["5"]["data"]["1"]["data"]
                          print(message_info)
                          clients.send(self.GenResponsMsg(message_info))
####################################
            # GET 100 LIKES COMMAND
            import re
            if "1200" in data.hex()[0:4] and b"/likes " in data:
                import re
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    player_id = default_id
                    
                    try:
                        id_match = re.search(r'/likes (\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                             
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:                             
                            temp_id = cleaned_message.split('/likes ')[1].split()[0].strip()
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Likes ID extraction error: {e}")
                        player_id = default_id               
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
                    if True:
	                    clients.send(self.GenResponsMsg("جاري إرسال الإعجابات..."))                    
	                    likes_info = send_likes(player_id)
	                    player_id = fix_num(player_id)
	                    clients.send(self.GenResponsMsg(likes_info)) 
                except Exception as e:
                    print(f"Likes Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "ID" in str(e) else f"[FF0000]خطأ في الإعجابات: {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()

#################################
            if "1200" in data.hex()[0:4] and b"/info" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[b][c][FF000F]♥
[FF0000َ]يتم البحث عن معلومات الحساب يرجى الإنتضار """

            if "1200" in data.hex()[0:4] and b"/DEV" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B]
مرحبٱ بكم في  [00ff00] كلان [FF0000]
  [ffffff]ㅤ ZIX TEAM

المطوربن 

ZIX OFFICIAL

[B][C][FF0000] الرجاء جمع 1500 قلوري في اليوم الواحد او سيتم طردك و يتم توقيف البوت لديك . 

[C][B]
مرحبٱ بك في كلان
ZIX  T E A M



لمعرفة الاوامر ارسل 
/َhelp

░█░█ㅤㅤㅤㅤㅤ
صانعين البوت

@XiZYELFI 
@XiZYELFI """
	                clients.send(self.GenResponsMsg(response_message))
	                
            if "1200" in data.hex()[0:4] and b"/FM" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[b][c][FF000F]أدخل للقائمة المهتم بها واجعلها ضمن قائمتك


[FF0000َ]اسلحة   7319✨471756
[C][B] [C][FF0000]--------------------------------
[FFFF00]فخمة   96919✨89441
[C][B] [FF0000]--------------------------------
[00FFFFَ]نادرة    9719✨822328
[C][B] [FF0000]--------------------------------
[FF00FFَ]رقصات 658✨8980942
[C][B] [FF0000]--------------------------------"""
	                clients.send(self.GenResponsMsg(response_message))
	                
            if "1200" in data.hex()[0:4] and b"/MAC" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[b][c][FF000F]المايك غير [ff3728] مبند"""
	                clients.send(self.GenResponsMsg(response_message))
	                
            if "1200" in data.hex()[0:4] and b"/HED" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[b][c][FF000F] نزل الايم لتحت و بعدين ارفعه
                        
 [C][B] [C][FF38E0]--------------------------------
 عندما تلعب بثلج ارفع الايم فوق بدون تنزيل
 [C][B] [C][FF00FF]--------------------------------
 عندما يركض الاعب في اتجاه معين ارفع الايم لليسار 
 [C][B] [C][F0000F]--------------------------------
 ارفع الdpi لل 800
 [C][B] [C][FF068E]--------------------------------
 ابحث عن قوقل عن برنامج موكرو
 [C][B] [C][FF0000]--------------------------------
 استخدم قفز لليد"""
	                clients.send(self.GenResponsMsg(response_message))

            if "1200" in data.hex()[0:4] and b"/DEV" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[b][c][FF000F]♥
[FF0000َ]مرحبا بكم في بوت الكلان
[C][B] [C][FF0000]--------------------------------
[FFFF00] 
[C][B] [FF0000]--------------------------------
[00FFFFَ] لحل اي مشكلة لديك تواصل معنا
[C][B] [FF0000]

[C][B] [FF0000]@zix official"""
	                clients.send(self.GenResponsMsg(response_message))                                    
            if "1200" in data.hex()[0:4] and b"/help" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B] بانل بوت صديق
	                
                                
[FFD799] إرسال البوت للاعب
	
[FF6347] /َadd <id>
	
[FF0000]--------------------------------
	
[FFD799] حذف البوت من الاعب  
	
[FF6347] /َremove <id>

[FF0000]--------------------------------
	
[FFD799] عرض جميع الاعبين الذين لديهم البوت
	
[FF6347] /َfreind <id>
	
[FF0000]--------------------------------
	
[FFD799]  حذف البوت لدى الجميع
	
[FF6347] /َremoves

[FF0000]--------------------------------

[FFD799]  تكلم مع ذكاء الاصطناعي
	
[FF6347] /َai """
	                clients.send(self.GenResponsMsg(response_message))
            
            if "1200" in data.hex()[0:4] and b"/help" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B]
                                
[FFD799] معلومات الاعب  
	
[FF6347] /َinfo <id>
	
[FF0000]--------------------------------
	
[FFD799] زيادة لايكات   
	
[FF6347] /َlikes <id>

[FF0000]--------------------------------
	
[FFD799] تحقق من بند  الحسابات
	
[FF6347] /َcheck <id>

[FF0000]--------------------------------

[FFD799]معرفة السيرفر الخاص باللاعب:
[1E90FF]/َregion <id>

[FF0000]--------------------------------

[FFD799] تحقق مايك مبند
[00FF00]/َMAC <id>

[FF0000]--------------------------------

[FFD799] تقوية الحساسية
[FB9200]/ََHED
				
"""
	                clients.send(self.GenResponsMsg(response_message))
            


          
            if "1200" in data.hex()[0:4] and b"/help" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B][FFD799] وضع البوت سولو
[FF02FE] /َsolo <id>                        

[EF98E0]--------------------------------

[FFD799] إضافة لاعب لمقبرة الروم
[FF02FE] /َroom <id>

[EF98E0]--------------------------------

[FFD799] إضافة لاعب لمقبرة سكواد
[FF02FE]/َspam <id>

[EF98E0]--------------------------------

[FFD799]إضافة لاعب لمقبرة تعليق سكواد
[FF02FE]/َlag [team code] 1-2-3

[EF98E0]--------------------------------

[FFD799]تعليق سكواد + بدأ إجباري
[FF02FE]/َGEM [team code]

[EF98E0]--------------------------------

[FFD799] رسائل الكلان
[FF02FE]/َF4X"""
	                clients.send(self.GenResponsMsg(response_message))
	                
	                	                
            if "1200" in data.hex()[0:4] and b"/help" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B][FFD799] بدأ إجباري 
[FF02FE] /َstart <id>                        

[EF98E0]--------------------------------

[FFD799] لاغ مع بدأ
[FF02FE] /َGEM <id>

[EF98E0]--------------------------------

[FFD799] إضافة لاعب لمقبرة سكواد
[FF02FE]/َspam <id>

[EF98E0]--------------------------------

[FFD799]خمسة في السكواد 
[FF02FE]/َ5

[EF98E0]--------------------------------

[FFD799]ستة في السكواد 
[FF02FE]/َ6

[EF98E0]--------------------------------

[FFD799] اربعه في السكواد
[FF02FE]/َ4"""
	                clients.send(self.GenResponsMsg(response_message))	                	                	                	                
            if "1200" in data.hex()[0:4] and b"/help" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B][FFD799] اعرف مين بسكواد صاحبك 
[FF02FE] /َstaute <id>                        

[EF98E0]--------------------------------

[FFD799] عرض المطورين
[FF02FE] /َDEV

[EF98E0]--------------------------------

[FFD799] سبام عادي
[FF02FE]/َsm <id>

[EF98E0]--------------------------------"""

            if "1200" in data.hex()[0:4] and b"/lag" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                response_message = f"""[C][B][FFD799]سيتم عمل مقبرة لاغ للسكواد """
	                clients.send(self.GenResponsMsg(response_message))


            if '1200' in data.hex()[0:4] and b'/lag' in data:
                try:
                    split_data = re.split(rb'/lag', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]ضع تيم كود", uid))
                        continue

                    room_id = command_parts[0]
                    repeat_count = 1

                    if len(command_parts) > 1 and command_parts[1].isdigit():
                        repeat_count = int(command_parts[1])

                    if repeat_count > 3:
                        repeat_count = 3
                        
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']
                    
                    if self.lag_thread and self.lag_thread.is_alive():
                        self.lag_thread.stop()
                        self.lag_thread.join()
                        
                    self.lag_thread = LagThread(socket_client, room_id, repeat_count, self.key, self.iv, uid)
                    self.lag_thread.start()
                    
                    clients.send(
                        self.GenResponsMsg(f"[C][B][FF8485]يتم عمل لاغ للاعب بقوة {repeat_count}", uid)
                    )
                    
                except Exception as e:
                    print(f"ضع امر /lag و بعده الايدي و بعده القوة {e}")
                    pass
            if "1200" in data.hex()[0:4] and b"/solo" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                leavee = self.leave_s()
                socket_client.send(leavee)

                sleep(0)

                change_to_solo = self.changes(0)
                socket_client.send(change_to_solo)

                clients.send(
                    self.GenResponsMsg(
                        f"[C][B][00FF00] تم الخروج من المجموعة.", uid
                    )
                )
            if '1200' in data.hex()[0:4] and b'/GEM' in data:
                try:
                    split_data = re.split(rb'/GEM', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]الرجاء إدخال كود الفريق. مثال:\n/GEM [TeamCode]", uid))
                        continue

                    team_code = command_parts[0]
                    
                    clients.send(
                        self.GenResponsMsg(f"[C][B][FFA500]بدء هجوم مزدوج ومكثف على الفريق كاملاً{team_code}...", uid)
                    )

                    start_packet = self.start_autooo()
                    leave_packet = self.leave_s()

                    attack_start_time = time.time()
                    while time.time() - attack_start_time < 45:
                        join_teamcode(socket_client, team_code, self.key, self.iv)
                        socket_client.send(start_packet)
                        socket_client.send(leave_packet)
                        time.sleep(0)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FF00]اكتمل الهجوم المزدوج على الفريق {team_code}!", uid)
                    )

                except Exception as e:
                    print(f"حدث خطأ في الامر : {e}")
                    try:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]حدث خطأ أثناء لاغ و بدأ اجباري للفريق", uid))
                    except:
                        pass     
                
            if "1200" in data.hex()[0:4] and b"/start" in data:
                try:
                    split_data = re.split(rb'/start', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]ضع التيم كود", uid))
                        continue

                    team_code = command_parts[0]
                    spam_count = 20

                    if len(command_parts) > 1 and command_parts[1].isdigit():
                        spam_count = int(command_parts[1])
                    
                    if spam_count > 50:
                        spam_count = 50

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FFA500]يتم البدأ إجباري...", uid)
                    )

                    join_teamcode(socket_client, team_code, self.key, self.iv)
                    time.sleep(0)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FF0000]يتم عمل سبام في وقت {spam_count} times!", uid)
                    )

                    start_packet = self.start_autooo()
                    for _ in range(spam_count):
                        socket_client.send(start_packet)
                        time.sleep(0)

                    leave_packet = self.leave_s()
                    socket_client.send(leave_packet)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FF00]سيتم البدأ", uid)
                    )

                except Exception as e:
                    print(f"حدث خطأ في امر /start {e}")
                    pass   
            if "1200" in data.hex()[0:4] and b"/rank" in data:
                try:
                    split_data = re.split(rb'/rank', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]ضع التيم كود", uid))
                        continue

                    team_code = command_parts[0]
                    spam_count = 20

                    if len(command_parts) > 1 and command_parts[1].isdigit():
                        spam_count = int(command_parts[1])
                    
                    if spam_count > 50:
                        spam_count = 50

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FFA500]يتم البدأ الان...", uid)
                    )

                    join_teamcode(socket_client, team_code, self.key, self.iv)
                    time.sleep(0)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FF0000]يتم الدخول {spam_count} times!", uid)
                    )

                    start_packet = self.start_autooo()
                    for _ in range(spam_count):
                        socket_client.send(start_packet)
                        time.sleep(0)

                    leave_packet = self.leave_s()
                    socket_client.send(leave_packet)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FF00]سيتم دخول بوتات", uid)
                    )

                except Exception as e:
                    print(f"حدث خطأ في الامر {e}")
            if "1200" in data.hex()[0:4] and b"/BMW" in data:
                try:
                    split_data = re.split(rb'/rank', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]ضع التيم كود", uid))
                        continue

                    team_code = command_parts[0]
                    spam_count = 20

                    if len(command_parts) > 1 and command_parts[1].isdigit():
                        spam_count = int(command_parts[1])
                    
                    if spam_count > 50:
                        spam_count = 50

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FFA500]يتم البدأ الان...", uid)
                    )

                    join_teamcode(socket_client, team_code, self.key, self.iv)
                    time.sleep(11)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FF0000]يتم الدخول {spam_count} times!", uid)
                    )

                    start_packet = self.start_autooo()
                    for _ in range(spam_count):
                        socket_client.send(start_packet)
                        time.sleep(0.1)

                    leave_packet = self.leave_s()
                    socket_client.send(leave_packet)

                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FF00]سيتم دخول بوتات", uid)
                    )

                except Exception as e:
                    print(f"حدث خطأ في الامر {e}")                    
                    
                    pass                       
                    
            if "1200" in data.hex()[0:4] and b"/add" in data:
                i = re.split("/add", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/add', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    print(room_data)
                    iddd = room_data[0]
                    numsc1 = room_data[1] if len(room_data) > 1 else None

                    if numsc1 is None:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]خطأ ، ضع امر /add و بعده الايدي و بعده رقم 5", uid
                            )
                        )
                    else:
                        numsc = int(numsc1) - 1
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        if int(numsc1) < 3 or int(numsc1) > 6:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000] Usage : /add <uid> <Squad Type>\n[ffffff]Example : \n/ add 12345678 4\n/ add 12345678 5", uid
                                )
                            )
                        else:
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(1)
                            packetfinal = self.changes(int(numsc))
                            socket_client.send(packetfinal)
                            
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)
                            iddd1 = parsed_data["5"]["data"]["1"]["data"]
                            invitessa = self.invite_skwad(iddd1)
                            socket_client.send(invitessa)
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
                                )
                            )
                            leaveee1 = True
                            while leaveee1:
                                if leaveee == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    sleep(5)
                                    socket_client.send(leavee)   
                                    leaveee = False
                                    leaveee1 = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]succes !", uid
                                        )
                                    )    
                                if pleaseaccept == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    socket_client.send(leavee)   
                                    leaveee1 = False
                                    pleaseaccept = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]Please accept the invite", uid
                                        )
                                    )   
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ inv 123[c]456[c]78 4\n/ inv 123[c]456[c]78 5", uid
                        )
                    ) 
            if "1200" in data.hex()[0:4] and b"/spy" in data:
                message = data.decode('utf-8', errors='ignore')
                message_parts = message.split() 
                roomid = None
                roomcode = None
                for part in message_parts:
                    digits = ''.join(filter(str.isdigit, part))
                    if digits:
                        roomid = int(digits)
                        break
                roomcode_match = re.search(r'roomcode=(\w+)', message)
                if roomcode_match:
                    roomcode = roomcode_match.group(1) 
                if roomid is not None and roomcode is not None:
                    packetmaker = self.join_room_chanel(roomid, roomcode)
                    socket_client.send(packetmaker)
                else:
                    pass	                
	                	                	                
            if "1200" in data.hex()[0:4] and b"/FOX" in data: 
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                sender_id = parsed_data["5"]["data"]["1"]["data"]
	                sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
 
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
         
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))


	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                               
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
              
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
               
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
        
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][0000F8]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF0000]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FFFF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][BBBF75]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][00FF00]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))
	                time.sleep(1)	                
	                response_message = f"""[C][B][FF00FF]F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X F4X"""	                
	                clients.send(self.GenResponsMsg(response_message))

	                	                	                	                	                	                	                
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    def  parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5055")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': freefire_version,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 11;en;BD;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": client_secret,"client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(paylod_token1)
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s

    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(
            self.id, self.password)
        g_token = token
        print(ip, port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)

        return token, key, iv


with open('accs.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())


def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()


max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(3)
    thread.start()
for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="3988968779", password="6ED969B7560905FAB29A8DCE6501D440F0ACA4CBC7492699987B15BD6A1B9590")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()
