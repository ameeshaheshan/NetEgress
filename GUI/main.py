import os
import sys
import asyncio
import threading
from datetime import datetime

# Add parent directory to path to import scanner modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kivymd.app import MDApp
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ListProperty
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDIconButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.card import MDCard
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.tab import MDTabsBase
from kivy.uix.floatlayout import FloatLayout

# SSRF Scanner Imports
try:
    from ssrf_scanner.core import SSRFScanner
    from ssrf_scanner.attack_modules import PayloadManager, AttackModules
    from ssrf_scanner.verification import Verifier
    from ssrf_scanner.reporting import Reporter
    from ssrf_scanner.remediation import RemediationEngine
except ImportError:
    print("[!] SSRF Scanner modules not found.")

KV = '''
ScreenManager:
    MainScreen:

<MainScreen>:
    name: "main"
    md_bg_color: [0.05, 0.05, 0.07, 1]
    
    BoxLayout:
        orientation: "vertical"
        padding: 20
        spacing: 15

        # Header
        BoxLayout:
            size_hint_y: None
            height: 60
            spacing: 10
            
            MDIconButton:
                icon: "shield-bug"
                theme_text_color: "Custom"
                text_color: [0, 0.8, 1, 1]
                pos_hint: {"center_y": .5}
            
            MDLabel:
                text: "NET-EGRESS: SSRF AUTOMATION PRO"
                theme_text_color: "Custom"
                text_color: [0, 0.8, 1, 1]
                bold: True
                pos_hint: {"center_y": .5}

        # Main Body - Two Columns
        BoxLayout:
            spacing: 20
            
            # Left Panel: All Settings (Scrollable)
            MDCard:
                size_hint_x: 0.5
                md_bg_color: [0.08, 0.08, 0.1, 1]
                padding: 15
                radius: 10
                
                ScrollView:
                    BoxLayout:
                        orientation: "vertical"
                        size_hint_y: None
                        height: self.minimum_height
                        spacing: 15
                        padding: [5, 5, 15, 5]
                        
                        MDLabel:
                            text: "TARGETING"
                            theme_text_color: "Custom"
                            text_color: [0, 0.8, 1, 1]
                            bold: True
                            size_hint_y: None
                            height: 30
                        
                        MDTextField:
                            id: target_url
                            hint_text: "Single URL"
                            text: "http://example.com/api?url="
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]
                        
                        MDTextField:
                            id: urls_file
                            hint_text: "URLs File Path"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]

                        BoxLayout:
                            size_hint_y: None
                            height: 45
                            spacing: 10
                            MDLabel:
                                text: "Method:"
                                theme_text_color: "Hint"
                                size_hint_x: None
                                width: 60
                            MDCheckbox:
                                id: method_get
                                active: True
                                group: "method"
                                size_hint: [None, None]
                                size: [40, 40]
                            MDLabel:
                                text: "GET"
                                size_hint_x: None
                                width: 40
                            MDCheckbox:
                                id: method_post
                                active: False
                                group: "method"
                                size_hint: [None, None]
                                size: [40, 40]
                            MDLabel:
                                text: "POST"
                                size_hint_x: None
                                width: 40
                        
                        MDTextField:
                            id: inject_param
                            hint_text: "Injected Parameter"
                            text: "url"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]
                        
                        MDTextField:
                            id: post_data
                            hint_text: "Additional POST Data"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]

                        HSeparator:

                        MDLabel:
                            text: "NETWORK & AUTH"
                            theme_text_color: "Custom"
                            text_color: [0, 0.8, 1, 1]
                            bold: True
                            size_hint_y: None
                            height: 30
                        
                        GridLayout:
                            cols: 3
                            spacing: 10
                            size_hint_y: None
                            height: 60
                            MDTextField:
                                id: rps
                                hint_text: "RPS"
                                text: "10"
                                mode: "fill"
                            MDTextField:
                                id: threads
                                hint_text: "Conn"
                                text: "50"
                                mode: "fill"
                            MDTextField:
                                id: timeout
                                hint_text: "Sec"
                                text: "10"
                                mode: "fill"

                        MDTextField:
                            id: proxy
                            hint_text: "Proxy URL"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]
                        
                        MDTextField:
                            id: user_agent
                            hint_text: "User-Agent"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]
                        
                        MDTextField:
                            id: cookie
                            hint_text: "Cookies"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]

                        HSeparator:

                        MDLabel:
                            text: "SYSTEM"
                            theme_text_color: "Custom"
                            text_color: [0, 0.8, 1, 1]
                            bold: True
                            size_hint_y: None
                            height: 30

                        MDTextField:
                            id: oob_domain
                            hint_text: "OOB Domain"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]
                        
                        MDTextField:
                            id: baseline_probes
                            hint_text: "Baseline Count"
                            text: "10"
                            mode: "fill"
                            fill_color: [0.12, 0.12, 0.15, 1]

                        BoxLayout:
                            size_hint_y: None
                            height: 40
                            spacing: 5
                            MDCheckbox:
                                id: test_mode
                                active: False
                                size_hint: [None, None]
                                size: [40, 40]
                            MDLabel:
                                text: "Safe Mode"
                                font_style: "Caption"
                            MDCheckbox:
                                id: verbose
                                active: True
                                size_hint: [None, None]
                                size: [40, 40]
                            MDLabel:
                                text: "Verbose"
                                font_style: "Caption"

                        HSeparator:

                        MDLabel:
                            text: "ATTACK PHASES"
                            theme_text_color: "Custom"
                            text_color: [0, 0.8, 1, 1]
                            bold: True
                            size_hint_y: None
                            height: 30
                        
                        BoxLayout:
                            size_hint_y: None
                            height: 40
                            MDCheckbox:
                                id: all_cb
                                active: True
                                size_hint: [None, None]
                                size: [40, 40]
                                on_active: root.toggle_all(self.active)
                            MDLabel:
                                text: "SELECT ALL"
                                theme_text_color: "Custom"
                                text_color: [1, 0.8, 0, 1]
                                bold: True

                        GridLayout:
                            id: phases_grid
                            cols: 1
                            size_hint_y: None
                            height: self.minimum_height

            # Right Panel: Output & Control
            BoxLayout:
                orientation: "vertical"
                size_hint_x: 0.5
                spacing: 15
                
                MDRaisedButton:
                    text: "LAUNCH MISSION" if not root.scanning else "EXECUTING..."
                    md_bg_color: [0, 0.5, 0.8, 1] if not root.scanning else [0.8, 0.2, 0.2, 1]
                    text_color: [1, 1, 1, 1]
                    size_hint_x: 1
                    height: 50
                    size_hint_y: None
                    on_release: root.start_scan_thread()
                    disabled: root.scanning

                MDCard:
                    orientation: "vertical"
                    padding: 15
                    md_bg_color: [0.1, 0.1, 0.12, 1]
                    elevation: 2
                    size_hint_y: None
                    height: 120
                    
                    BoxLayout:
                        size_hint_y: None
                        height: 30
                        MDLabel:
                            text: "PROGRESS"
                            theme_text_color: "Hint"
                        MDLabel:
                            id: progress_label
                            text: "0%"
                            halign: "right"
                            theme_text_color: "Custom"
                            text_color: [0, 0.8, 1, 1]
                    
                    MDProgressBar:
                        id: progress_bar
                        value: root.progress_val
                        color: [0, 0.8, 1, 1]
                        size_hint_y: None
                        height: 10
                    
                    MDLabel:
                        text: root.status_msg
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        height: 30

                MDCard:
                    orientation: "vertical"
                    padding: 5
                    md_bg_color: [0.05, 0.05, 0.05, 1]
                    elevation: 1
                    
                    ScrollView:
                        id: log_scroll
                        MDLabel:
                            id: log_output
                            text: root.logs
                            theme_text_color: "Custom"
                            text_color: [0.4, 0.8, 0.4, 1]
                            size_hint_y: None
                            height: self.texture_size[1]
                            valign: "top"

        # Stats Bar
        MDCard:
            size_hint_y: None
            height: 40
            md_bg_color: [0, 0, 0, 1]
            padding: [20, 0]
            BoxLayout:
                MDLabel:
                    text: "VULNERABILITIES: " + str(int(root.vuln_count))
                    theme_text_color: "Custom"
                    text_color: [1, 0.2, 0.2, 1] if root.vuln_count > 0 else [0.4, 0.4, 0.4, 1]
                    bold: True
                MDLabel:
                    text: "REQUESTS: " + str(int(root.req_count))
                    theme_text_color: "Hint"
                    halign: "right"

<HSeparator@Widget>:
    size_hint_y: None
    height: 1
    canvas:
        Color:
            rgba: [0.2, 0.2, 0.25, 1]
        Rectangle:
            pos: self.pos
            size: self.size
'''

PHASES = [
    'local_ips', 'cloud_metadata', 'protocol_confusion',
    'crlf_injection', 'bypass_encoding', 'dns_rebinding',
    'port_scanning', 'parameter_fuzzing', 'header_injection',
    'xxe_ssrf'
]

class MainScreen(Screen):
    progress_val = NumericProperty(0)
    logs = StringProperty(" > System Ready.\\n")
    status_msg = StringProperty("Idle")
    vuln_count = NumericProperty(0)
    req_count = NumericProperty(0)
    scanning = BooleanProperty(False)
    selected_phases = ListProperty(PHASES[:])

    def __init__(self, **kw):
        super().__init__(**kw)
        self.loop = asyncio.new_event_loop()
        thread = threading.Thread(target=self._run_event_loop, daemon=True)
        thread.start()
        Clock.schedule_once(self.populate_phases)

    def populate_phases(self, dt):
        grid = self.ids.phases_grid
        for phase in PHASES:
            item = Builder.load_string(f'''
BoxLayout:
    orientation: "horizontal"
    size_hint_y: None
    height: 35
    MDCheckbox:
        id: cb_{phase}
        active: True
        size_hint: [None, None]
        size: [35, 35]
        on_active: app.root.get_screen("main").on_phase_toggle("{phase}", self.active)
    MDLabel:
        text: "{phase.replace("_", " ").upper()}"
        font_style: "Caption"
        theme_text_color: "Hint"
            ''')
            grid.add_widget(item)

    def _run_event_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def on_phase_toggle(self, phase, active):
        if active:
            if phase not in self.selected_phases:
                self.selected_phases.append(phase)
        else:
            if phase in self.selected_phases:
                self.selected_phases.remove(phase)
        self.ids.all_cb.active = (len(self.selected_phases) == len(PHASES))

    def toggle_all(self, active):
        grid = self.ids.phases_grid
        for child in grid.children:
            for widget in child.children:
                if isinstance(widget, MDCheckbox):
                    widget.active = active
        self.selected_phases = PHASES[:] if active else []

    def add_log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs += f"[{timestamp}] {msg}\\n"
        Clock.schedule_once(lambda dt: self._scroll_logs())

    def _scroll_logs(self):
        self.ids.log_scroll.scroll_y = 0

    def start_scan_thread(self):
        url = self.ids.target_url.text.strip()
        urls_file = self.ids.urls_file.text.strip()
        if not url and not urls_file:
            self.status_msg = "Error: No Target"
            return
        
        self.scanning = True
        self.progress_val = 0
        self.vuln_count = 0
        self.req_count = 0
        self.logs = f" > Starting session...\\n"
        
        params = {
            'url': url,
            'urls_file': urls_file,
            'method': 'POST' if self.ids.method_post.active else 'GET',
            'param': self.ids.inject_param.text.strip(),
            'post_data': self.ids.post_data.text.strip(),
            'rps': int(self.ids.rps.text or 10),
            'concurrent': int(self.ids.threads.text or 50),
            'timeout': int(self.ids.timeout.text or 10),
            'proxy': self.ids.proxy.text.strip() or None,
            'user_agent': self.ids.user_agent.text.strip() or None,
            'cookie': self.ids.cookie.text.strip() or None,
            'oob_domain': self.ids.oob_domain.text.strip() or None,
            'baseline_probes': int(self.ids.baseline_probes.text or 10),
            'test_mode': self.ids.test_mode.active,
            'verbose': self.ids.verbose.active,
            'phases': self.selected_phases[:]
        }
        asyncio.run_coroutine_threadsafe(self.execute_scan(params), self.loop)

    async def execute_scan(self, p):
        try:
            payload_manager = PayloadManager('payloads')
            attack_modules = AttackModules(payload_manager)
            verifier = Verifier()
            
            cookies = {}
            if p['cookie']:
                for part in p['cookie'].split(';'):
                    if '=' in part:
                        k, v = part.strip().split('=', 1)
                        cookies[k.strip()] = v.strip()

            targets = []
            if p['url']: targets.append(p['url'])
            if p['urls_file'] and os.path.exists(p['urls_file']):
                with open(p['urls_file'], 'r') as f:
                    targets.extend([l.strip() for l in f if l.strip()])
            
            if not targets:
                Clock.schedule_once(lambda dt: self.add_log("No targets found."))
                return

            for target_url in targets:
                Clock.schedule_once(lambda dt: self.add_log(f"Engaging: {target_url}"))
                async with SSRFScanner(
                    target_url=target_url,
                    requests_per_second=p['rps'],
                    max_concurrent=p['concurrent'],
                    timeout=p['timeout'],
                    proxy=p['proxy'],
                    user_agent=p['user_agent'],
                    cookies=cookies
                ) as scanner:
                    await scanner.establish_baseline(p['baseline_probes'], method=p['method'], param=p['param'])
                    if p['test_mode']: continue

                    all_payloads = attack_modules.get_all_attack_payloads(target_url)
                    filtered = {k: v for k, v in all_payloads.items() if k in p['phases']}
                    test_queue = []
                    for phase, payloads in filtered.items():
                        for pl in payloads: test_queue.append((phase, pl))
                    
                    total = len(test_queue)
                    for i, (phase, payload) in enumerate(test_queue):
                        p_val = payload['payload'] if isinstance(payload, dict) else payload
                        param = payload.get('param', p['param']) if isinstance(payload, dict) else p['param']
                        result = await scanner.test_payload(p_val, param=param, method=p['method'])
                        Clock.schedule_once(lambda dt: setattr(self, 'req_count', self.req_count + 1))
                        
                        prog = int(((i+1)/total) * 100)
                        def upd(dt, v=prog):
                            self.progress_val = v
                            self.ids.progress_label.text = f"{v}%"
                        Clock.schedule_once(upd)

                        if result:
                            v = verifier.verify_vulnerability(result, p['oob_domain'])
                            if v.get('vulnerable'):
                                Clock.schedule_once(lambda dt: setattr(self, 'vuln_count', self.vuln_count + 1))
                                Clock.schedule_once(lambda dt: self.add_log(f"[!] {v.get('vulnerability_type')}"))

            Clock.schedule_once(lambda dt: setattr(self, 'status_msg', "Finished"))
        except Exception as e:
            Clock.schedule_once(lambda dt: self.add_log(f"Error: {str(e)}"))
        finally:
            Clock.schedule_once(lambda dt: setattr(self, 'scanning', False))

class SSRFScannerApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Cyan"
        Window.size = (1150, 850)
        return Builder.load_string(KV)

if __name__ == "__main__":
    SSRFScannerApp().run()
