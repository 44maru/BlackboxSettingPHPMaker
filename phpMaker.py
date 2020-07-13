import logging.config
import os
import sys
import datetime

import jctconv

LOG_CONF = "./logging.conf"
logging.config.fileConfig(LOG_CONF)

from kivy.app import App
from kivy.config import Config
Config.set('modules', 'inspector', '')  # Inspectorを有効にする
Config.set('graphics', 'width', 480)
Config.set('graphics', 'height', 280)
Config.set('graphics', 'maxfps', 20)  # フレームレートを最大で20にする
Config.set('graphics', 'resizable', 0)  # Windowの大きさを変えられなくする
Config.set('input', 'mouse', 'mouse,disable_multitouch')
from kivy.core.text import LabelBase, DEFAULT_FONT
from kivy.core.window import Window
from kivy.resources import resource_add_path
from kivy.uix.screenmanager import Screen

if hasattr(sys, "_MEIPASS"):
    resource_add_path(sys._MEIPASS)

EMPTY = ""
SIZE_S = "S"
SIZE_M = "M"
SIZE_L = "L"
SIZE_XL = "XL"
INDEX_TWITTER = 21
INDEX_EMAIL = 9
INDEX_FIRST_NAME = 3
INDEX_LAST_NAME = 2
INDEX_ADDRESS = 7
INDEX_POST_CODE = 4
INDEX_CITY = 6
INDEX_REGION = 5
INDEX_PHONE = 8
INDEX_PAY_TYPE = 13
INDEX_CARD_NUMBER = 14
INDEX_CARD_LIMIT_MONTH = 15
INDEX_CARD_LIMIT_YEAR = 16
INDEX_CARD_CVV = 17
INDEX_ITEM_NO_1 = 4
INDEX_ITEM_NO_2 = 5
INDEX_ITEM_SIZE = 2

ID_MESSAGE = "message"

OUT_FILE_NAME = "blackbox-setting.php"
CHECKOUT_PROFILES_JSON = "checkoutprofiles.json"
UTF8 = "utf8"
SJIS = "sjis"

CONFIG_TXT = "./config.txt"
PROXY_TXT = "./proxy.txt"
CONFIG_DICT = {}
CONFIG_KEY_DELAY ="DELAY"
CONFIG_KEY_START_WEEK ="START_WEEK"
CONFIG_KEY_START_HHMM ="START_HHMM"
CONFIG_KEY_DISCORD_HOOK_URL = "webhookURL"
CONFIG_KEY_DISCORD_MESSAGE = "discordmessage"
CONFIG_KEY_2CAPTCHA_API = "2captchaAPI"
CONFIG_KEY_RESTOCK = "RESTOCK"
CONFIG_KEY_RESTOCK_START_WEEK = "RESTOCK_START_WEEK"
CONFIG_KEY_RESTOCK_START_HHMM = "RESTOCK_START_HHMM"
PROXY_LIST = []

OUT_FILE_CONTENTS_HEADER = """<?php
// 
// blackbox-setting.php
// http://buzz-coin.work/blackbox-setting-v3.php?id=1 指定された設定データを $secretで暗号化した文字列で返す
// http://buzz-coin.work/blackbox-setting-v3.php?id=2
//
// http://buzz-coin.work/blackbox-setting-v2.php?id=2&mode=check の場合はproxyが指定通りかチェック 
//

mb_language("Japanese");
mb_internal_encoding('UTF-8');
header('Content-Type: text/html; charset=utf-8');

$settings = array();
"""

OUT_FILE_CONTENTS_TEMPLATE = """
$setting = array();
$setting["secret"]		= "033ea2525cd12345033ea2525cd12345";
$setting["category"]	= "{}";
$setting["codes1"]		= "{}";
$setting["sizes1"]		= "{}";
$setting["codes2"]		= "";
$setting["sizes2"]		= "";
$setting["codes3"]		= "";
$setting["sizes3"]		= "";
$setting["proxy"]		= "{}";
$setting["start_week"]	= {};
$setting["start_hhmm"]	= "{}";
$setting["last_name"]	= "{}";
$setting["first_name"]	= "{}";
$setting["email"]		= "{}";
$setting["tel"]			= "{}";
$setting["pref"]		= " {}";
$setting["address"]		= "{}";
$setting["address2"]	= "{}";
$setting["zip"]			= "{}";
$setting["card_type"] 	= "{}";
$setting["card_number"]	= "{}";
$setting["card_month"]	= "{}";
$setting["card_year"]	= "{}";
$setting["vval"]		= "{}";
$setting["cash"]		= true;
$setting["delay"]		= {};
$setting["discordhookurl"] = "{}";
$setting["discordmessage"] = "{}";
$setting["recaptchabypass"]	= false;
$setting["twocaptchabypass"]	= {};
$setting["apikey"]	= "{}";
$setting["restock_use"] = {};
$setting["restock_start_week"]	= {};
$setting["restock_start_hhmm"]	= "{}";
$settings[{}] = $setting;
"""

OUT_FILE_CONTENTS_HOOTER = """///////////////////////////////////
//
// 1.パラメーターチェック
//
///////////////////////////////////
extract($_GET);
if(!compact('id')){
	echo "error #1"; exit;
}
if(!array_key_exists($id,$settings)){
	echo "error #2 no setting id={$id}"; exit;
}

///////////////////////////////////
//
// 2. checkモード処理
//
///////////////////////////////////
if(compact('mode') && $mode=="check"){

	$proxy = explode(",",$settings[$id]["proxy"]);
	if(count($proxy)<=1)$proxy = explode(":",$settings[$id]["proxy"]);

	if($_SERVER["HTTP_X_REAL_IP"]==$proxy[0]){
		echo "OK!! your ip is {$_SERVER["HTTP_X_REAL_IP"]}";
	}elseif($_SERVER["REMOTE_ADDR"]==$proxy[0]){
		echo "OK!! your ip is {$_SERVER["REMOTE_ADDR"]}";
	}else{
		echo "Not Good! Your ip {$_SERVER["REMOTE_ADDR"]} is defferent from setting id={$id}";
	}

}else{
///////////////////////////////////
//
// 3. 設定データ返送処理
//
///////////////////////////////////

	$out = array();
	foreach($settings[$id] as $key => $value){
		$out[] = "{$key}={$value}";
	}
	$data_plain = json_encode($out);
	//$data_plain = json_encode($settings[$id]);
	//echo "<html><head></head><body><data>". $data_plain ."</data></body></html>";
	$encrypted = CryptoJSAesEncrypt($settings[$id]["secret"],$data_plain);
	echo "<html><head></head><body><data>". $encrypted ."</data></body></html>";
}

exit;


function CryptoJSAesEncrypt($passphrase, $plain_text){

    $salt	= openssl_random_pseudo_bytes(256);
    $iv		= openssl_random_pseudo_bytes(16);

    $iterations = 999;  
    $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);

    $encrypted_data = openssl_encrypt($plain_text, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);

    $data = array("ciphertext" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "salt" => bin2hex($salt));
    return json_encode($data);
}

?>"""


class JsonMakerScreen(Screen):
    def __init__(self, **kwargs):
        super(JsonMakerScreen, self).__init__(**kwargs)
        self._file = Window.bind(on_dropfile=self._on_file_drop)

    def _on_file_drop(self, window, file_path):
        self.dump_out_file(file_path.decode(UTF8))

    def dump_out_file(self, file_path):
        global log
        try:
            self.dump_out_file_core(file_path)
        except Exception as e:
            self.disp_messg_err("{}の出力に失敗しました。".format(OUT_FILE_NAME))
            log.exception("{}の出力に失敗しました。%s".format(OUT_FILE_NAME), e)

    def dump_out_file_core(self, file_path):
        index = 1
        proxy_index = 0

        with open(OUT_FILE_NAME, "w", encoding=UTF8) as f:

            f.write(OUT_FILE_CONTENTS_HEADER)

            for line in open(file_path, "r", encoding=UTF8):
                line = line[:-1]
                items = line.split("\t")
                if items[0] == "*S":
                    last_name = items[INDEX_LAST_NAME]
                    first_name = items[INDEX_FIRST_NAME]
                    email = items[INDEX_EMAIL]
                    phone_number = items[INDEX_PHONE]
                    state = items[INDEX_REGION]
                    city = items[INDEX_CITY]
                    detail_address = items[INDEX_ADDRESS]
                    zip_code = items[INDEX_POST_CODE].replace("-", "")
                    card_type = items[INDEX_PAY_TYPE].lower().replace(" ", "_").replace("mastercard", "master")

                    if card_type == "americanexpress":
                        card_type = "american_express"

                    if card_type == "代金引換":
                        today = datetime.date.today()
                        card_type = "visa"
                        card_number = ""
                        card_limit_month = "%02d" % today.month
                        card_limit_year = today.year
                        cvv = ""
                    else:
                        card_number = items[INDEX_CARD_NUMBER]
                        card_limit_month = items[INDEX_CARD_LIMIT_MONTH]
                        if card_limit_month != EMPTY:
                            card_limit_month = "%02d" % (int(card_limit_month))
                        card_limit_year = items[INDEX_CARD_LIMIT_YEAR]
                        if card_limit_year != EMPTY:
                            card_limit_year = "20" + card_limit_year
                        cvv = items[INDEX_CARD_CVV]

                elif items[0] == "*I":
                    item_no_1 = items[INDEX_ITEM_NO_1]
                    item_no_2 = items[INDEX_ITEM_NO_2]
                    if item_no_2.lower() == "all":
                        item_no_2 = EMPTY

                    size = self.format_size(items[INDEX_ITEM_SIZE])

                    if len(PROXY_LIST) <= proxy_index:
                        proxy_index = 0

                    proxy = self.get_proxy_info(proxy_index)

                    apiKey = CONFIG_DICT[CONFIG_KEY_2CAPTCHA_API]
                    if apiKey == EMPTY:
                        twocaptchabypass = "false"
                    else:
                        twocaptchabypass = "true"


                    f.write(OUT_FILE_CONTENTS_TEMPLATE.format(
                        item_no_2, item_no_1, size, proxy, CONFIG_DICT[CONFIG_KEY_START_WEEK],
                        CONFIG_DICT[CONFIG_KEY_START_HHMM], last_name, first_name, email,
                        phone_number, state, city, detail_address, zip_code, card_type, card_number,
                        card_limit_month, card_limit_year, cvv, CONFIG_DICT[CONFIG_KEY_DELAY],
                        CONFIG_DICT[CONFIG_KEY_DISCORD_HOOK_URL], CONFIG_DICT[CONFIG_KEY_DISCORD_MESSAGE],
                        twocaptchabypass, apiKey,
                        CONFIG_DICT[CONFIG_KEY_RESTOCK], 
                        CONFIG_DICT[CONFIG_KEY_RESTOCK_START_WEEK],
                        CONFIG_DICT[CONFIG_KEY_RESTOCK_START_HHMM],
                        index
                    ))
                    index += 1
                    proxy_index += 1

            f.write(OUT_FILE_CONTENTS_HOOTER)

        self.disp_messg("{}を出力しました".format(OUT_FILE_NAME))

    def get_proxy_info(self, proxy_index):
        if len(PROXY_LIST) > 0:
            proxy = PROXY_LIST[proxy_index]
        else:
            proxy = EMPTY
        return proxy

    def disp_messg(self, msg):
        self.ids[ID_MESSAGE].text = msg
        self.ids[ID_MESSAGE].color = (0, 0, 0, 1)

    def disp_messg_err(self, msg):
        self.ids[ID_MESSAGE].text = "{}\n詳細はログファイルを確認してください。".format(msg)
        self.ids[ID_MESSAGE].color = (1, 0, 0, 1)

    @staticmethod
    def format_size(size):
        global log
        size = jctconv.normalize(size.upper())
        if size == SIZE_S:
            return "Small"
        elif size == SIZE_M:
            return "Medium"
        elif size == SIZE_L:
            return "Large"
        elif size == SIZE_XL:
            return "XLarge"
        else:
            return size


class PhpMakerApp(App):
    def build(self):
        return JsonMakerScreen()


def setup_config():
    load_config()
    load_proxy()



def load_proxy():
    if not os.path.exists(PROXY_TXT):
        return

    for line in open(PROXY_TXT, "r"):
        PROXY_LIST.append(line.replace("\n", ""))


def load_config():
    for line in open(CONFIG_TXT, "r", encoding=SJIS):
        items = line.replace("\n", "").split("=")

        if len(items) != 2:
            continue

        CONFIG_DICT[items[0]] = items[1]


if __name__ == '__main__':
    log = logging.getLogger('my-log')
    setup_config()
    LabelBase.register(DEFAULT_FONT, "ipaexg.ttf")
    PhpMakerApp().run()
