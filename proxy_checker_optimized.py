import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from queue import Queue, Empty
from collections import defaultdict
from pathlib import Path
from datetime import datetime
import requests
import time
import csv
import sys
import json

# Отключение предупреждений SSL
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================

URL_HISTORY_FILE = "url_history.json"
URL_HISTORY_MAX = 20  # максимум записей в истории

TEST_SITES = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.reddit.com",
    "https://www.bing.com",
    "https://httpbin.org/get",
]


@dataclass
class Config:
    """Конфигурация приложения"""
    TEST_URL: str = "https://www.google.com"
    GEO_API_URL: str = "http://ip-api.com/json"
    MAX_WORKERS: int = 10
    DEFAULT_ATTEMPTS: int = 3
    DEFAULT_TIMEOUT: int = 5
    OUTPUT_FOLDER: str = "proxy_results"
    LOG_FILENAME: str = "log.txt"
    CSV_FILENAME: str = "results.csv"


# =============================================================================
# МОДЕЛИ ДАННЫХ
# =============================================================================

@dataclass
class ProxyResult:
    """Структурированный результат теста прокси"""
    proxy: str
    success_percent: float = 0.0
    latency_ms: float = 0.0
    avg_speed_bps: float = 0.0
    ip: str = "-"
    country: str = "-"
    city: str = "-"
    isp: str = "-"
    is_hosting: bool = False
    ip_classification: str = "Failed"

    @property
    def speed_kbps(self) -> float:
        """Скорость в KB/s"""
        return self.avg_speed_bps / 1024

    @property
    def is_successful(self) -> bool:
        """Проверка успешности теста"""
        return self.success_percent > 0


@dataclass
class GeoData:
    """Данные геолокации"""
    ip: str = "-"
    country: str = "-"
    city: str = "-"
    isp: str = "-"
    is_hosting: bool = False

    @property
    def classification(self) -> str:
        """Классификация IP на основе статуса хостинга"""
        return "Datacenter" if self.is_hosting else "Residential"


# =============================================================================
# ОСНОВНАЯ ЛОГИКА
# =============================================================================

class ProxyNormalizer:
    """Обработка нормализации формата прокси"""
    
    PROTOCOLS = ("http://", "https://", "socks5://", "socks5h://")
    
    @staticmethod
    def normalize(raw_proxy: str) -> Optional[str]:
        """
        Нормализует строку прокси в формат, совместимый с requests.
        Добавляет префикс http:// если протокол не указан.
        """
        raw_proxy = raw_proxy.strip()
        if not raw_proxy:
            return None
        
        if any(raw_proxy.startswith(p) for p in ProxyNormalizer.PROTOCOLS):
            return raw_proxy
        
        return f"http://{raw_proxy}"


class GeoResolver:
    """Определение геолокации и качества IP"""
    
    def __init__(self, api_url: str, timeout: int):
        self.api_url = api_url
        self.timeout = timeout
    
    def resolve(self, proxy_dict: Dict[str, str]) -> GeoData:
        """Получение данных геолокации через прокси"""
        try:
            response = requests.get(
                self.api_url, 
                proxies=proxy_dict, 
                timeout=self.timeout
            )
            data = response.json()
            
            return GeoData(
                ip=data.get("query", "-"),
                country=data.get("country", "-"),
                city=data.get("city", "-"),
                isp=data.get("isp", "-"),
                is_hosting=data.get("hosting", False)
            )
        except Exception:
            return GeoData()


class ProxyTester:
    """Тестирование производительности и доступности отдельных прокси"""
    
    def __init__(self, config: Config):
        self.config = config
        self.geo_resolver = GeoResolver(config.GEO_API_URL, config.DEFAULT_TIMEOUT)
    
    def test(self, raw_proxy: str, attempts: int, timeout: int) -> tuple[ProxyResult, str]:
        """
        Тестирование прокси с несколькими попытками.
        Возвращает: (ProxyResult, сообщение_лога)
        """
        proxy = ProxyNormalizer.normalize(raw_proxy)
        if not proxy:
            return ProxyResult(proxy=raw_proxy), f"❌ Неверный формат прокси: {raw_proxy}\n"
        
        proxy_dict = {"http": proxy, "https": proxy}
        
        success_count = 0
        total_latency = 0.0
        total_speed = 0.0
        geo_data: Optional[GeoData] = None
        log_lines = []
        
        # Выполнение попыток
        for attempt in range(1, attempts + 1):
            try:
                start_time = time.time()
                log_lines.append(f"  Попытка {attempt}/{attempts}...")
                
                response = requests.get(
                    self.config.TEST_URL,
                    proxies=proxy_dict,
                    timeout=timeout
                )
                
                elapsed = time.time() - start_time
                latency_ms = elapsed * 1000
                content_size = len(response.content)
                speed_bps = content_size / elapsed
                
                success_count += 1
                total_latency += latency_ms
                total_speed += speed_bps
                
                log_lines.append(
                    f"    ✓ OK | Задержка: {latency_ms:.0f}мс | Скорость: {speed_bps/1024:.2f} KB/s"
                )
                
                # Получение геоданных только один раз при первом успехе
                if geo_data is None:
                    geo_data = self.geo_resolver.resolve(proxy_dict)
                    log_lines.append(
                        f"    ℹ IP: {geo_data.ip} | Страна: {geo_data.country} | {geo_data.classification}"
                    )
                
            except requests.exceptions.RequestException as e:
                log_lines.append(f"    ✗ FAIL | {e.__class__.__name__}: {str(e)[:80]}")
            except Exception as e:
                log_lines.append(f"    ✗ ERROR | {e.__class__.__name__}: {str(e)[:80]}")
        
        # Формирование результата
        if success_count > 0 and geo_data:
            result = ProxyResult(
                proxy=raw_proxy,
                success_percent=(success_count / attempts) * 100,
                latency_ms=total_latency / success_count,
                avg_speed_bps=total_speed / success_count,
                ip=geo_data.ip,
                country=geo_data.country,
                city=geo_data.city,
                isp=geo_data.isp,
                is_hosting=geo_data.is_hosting,
                ip_classification=geo_data.classification
            )
        else:
            result = ProxyResult(proxy=raw_proxy)
        
        # Форматирование лога
        separator = "=" * 70
        log_message = f"\n{separator}\n"
        log_message += f"Тестирование: {raw_proxy}\n"
        log_message += "\n".join(log_lines) + "\n"
        
        if result.is_successful:
            log_message += f"  ► Успешно: {result.success_percent:.0f}% | "
            log_message += f"Средняя задержка: {result.latency_ms:.0f}мс | "
            log_message += f"Средняя скорость: {result.speed_kbps:.2f} KB/s\n"
        else:
            log_message += "  ► ПОЛНЫЙ ПРОВАЛ\n"
        
        return result, log_message


# =============================================================================
# GUI ПРИЛОЖЕНИЕ
# =============================================================================

class ProxyCheckerGUI:
    """Главное GUI приложение с MVC-подобной структурой"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = Config()
        self.tester = ProxyTester(self.config)
        
        # Состояние
        self.proxy_queue: Queue = Queue()
        self.results: List[ProxyResult] = []
        self.processed_count = 0
        self.total_proxies = 0
        self.is_running = False
        self.lock = threading.Lock()
        self.log_file = None
        
        # Компоненты GUI
        self.widgets = {}
        self.url_history: List[str] = self._load_url_history()
        self._build_gui()
    
    # -------------------------------------------------------------------------
    # Построение GUI
    # -------------------------------------------------------------------------
    
    def _build_gui(self):
        """Построение полного GUI"""
        self.root.title("🚀 Proxy Checker Pro")
        self.root.geometry("720x620")
        self.root.resizable(False, False)
        self.root.configure(bg='#2b2b2b')
        
        # Стили
        self.styles = {
            'bg': '#2b2b2b',
            'fg': '#ffffff',
            'input_bg': '#3c3c3c',
            'input_fg': '#ffffff',
            'button_bg': '#0078d4',
            'button_fg': '#ffffff',
            'success': '#28a745',
            'error': '#dc3545',
            'font': ('Segoe UI', 10),
            'font_bold': ('Segoe UI', 10, 'bold'),
            'font_title': ('Segoe UI', 12, 'bold'),
        }
        
        self._build_header()
        self._build_input_section()
        self._build_log_section()
        self._build_status_section()
        self._build_controls()
    
    def _build_header(self):
        """Построение заголовка"""
        header = tk.Frame(self.root, bg=self.styles['bg'])
        header.pack(pady=15)
        
        tk.Label(
            header,
            text="🚀 Proxy Checker Pro",
            font=self.styles['font_title'],
            bg=self.styles['bg'],
            fg=self.styles['button_bg']
        ).pack()
    
    def _build_input_section(self):
        """Построение секции ввода данных"""
        frame = tk.Frame(self.root, bg=self.styles['bg'])
        frame.pack(padx=24, pady=(0, 8), fill='x')

        # Единая ширина колонки меток
        LABEL_W = 14
        BTN_W   = 8   # ширина всех кнопок (символы)

        # ── Строка 0: Файл прокси ──────────────────────────────────────────
        tk.Label(
            frame, text="Файл прокси:", width=LABEL_W, anchor='w',
            font=self.styles['font_bold'], bg=self.styles['bg'], fg=self.styles['fg']
        ).grid(row=0, column=0, sticky='w', pady=6)

        self.widgets['file_entry'] = tk.Entry(
            frame, font=self.styles['font'],
            bg=self.styles['input_bg'], fg=self.styles['input_fg'],
            insertbackground=self.styles['fg'], relief='flat'
        )
        self.widgets['file_entry'].grid(row=0, column=1, sticky='ew', pady=6, padx=(0, 6))

        tk.Button(
            frame, text="Обзор", width=BTN_W,
            command=self._browse_file,
            bg=self.styles['button_bg'], fg=self.styles['button_fg'],
            font=self.styles['font'], cursor='hand2', relief='flat'
        ).grid(row=0, column=2, sticky='ew', pady=6)

        # ── Строка 1: Тест URL ────────────────────────────────────────────
        tk.Label(
            frame, text="Тест URL:", width=LABEL_W, anchor='w',
            font=self.styles['font_bold'], bg=self.styles['bg'], fg=self.styles['fg']
        ).grid(row=1, column=0, sticky='w', pady=6)

        self.widgets['url_combo'] = tk.Entry(
            frame, font=self.styles['font'],
            bg=self.styles['input_bg'], fg=self.styles['input_fg'],
            insertbackground=self.styles['fg'], relief='flat'
        )
        self.widgets['url_combo'].insert(0, self.url_history[0] if self.url_history else self.config.TEST_URL)
        self.widgets['url_combo'].grid(row=1, column=1, sticky='ew', pady=6, padx=(0, 6))
        self._bind_clipboard(self.widgets['url_combo'])

        def _show_url_menu():
            menu = tk.Menu(self.root, tearoff=0,
                           bg=self.styles['input_bg'], fg=self.styles['fg'],
                           activebackground=self.styles['button_bg'],
                           activeforeground=self.styles['button_fg'],
                           font=self.styles['font'])

            def _set_url(s):
                self.widgets['url_combo'].delete(0, tk.END)
                self.widgets['url_combo'].insert(0, s)

            if self.url_history:
                menu.add_command(label="⏱ Недавние:", state='disabled')
                for site in self.url_history:
                    menu.add_command(label=f"  {site}", command=lambda s=site: _set_url(s))
                menu.add_separator()

            menu.add_command(label="🌐 Популярные:", state='disabled')
            for site in TEST_SITES:
                menu.add_command(label=f"  {site}", command=lambda s=site: _set_url(s))

            btn = url_drop_btn
            menu.post(btn.winfo_rootx(), btn.winfo_rooty() + btn.winfo_height())

        url_drop_btn = tk.Button(
            frame, text="▼", width=BTN_W,
            command=_show_url_menu,
            bg=self.styles['button_bg'], fg=self.styles['button_fg'],
            font=self.styles['font'], cursor='hand2', relief='flat'
        )
        url_drop_btn.grid(row=1, column=2, sticky='ew', pady=6)

        # ── Строка 2: Попытки + Таймаут ───────────────────────────────────
        tk.Label(
            frame, text="Попытки:", width=LABEL_W, anchor='w',
            font=self.styles['font'], bg=self.styles['bg'], fg=self.styles['fg']
        ).grid(row=2, column=0, sticky='w', pady=6)

        inner = tk.Frame(frame, bg=self.styles['bg'])
        inner.grid(row=2, column=1, columnspan=2, sticky='ew', pady=6)

        self.widgets['attempts'] = tk.Entry(
            inner, width=8, font=self.styles['font'],
            bg=self.styles['input_bg'], fg=self.styles['input_fg'],
            insertbackground=self.styles['fg'], relief='flat', justify='center'
        )
        self.widgets['attempts'].insert(0, str(self.config.DEFAULT_ATTEMPTS))
        self.widgets['attempts'].pack(side='left')

        tk.Label(
            inner, text="Таймаут (сек):", anchor='w',
            font=self.styles['font'], bg=self.styles['bg'], fg=self.styles['fg']
        ).pack(side='left', padx=(20, 8))

        self.widgets['timeout'] = tk.Entry(
            inner, width=8, font=self.styles['font'],
            bg=self.styles['input_bg'], fg=self.styles['input_fg'],
            insertbackground=self.styles['fg'], relief='flat', justify='center'
        )
        self.widgets['timeout'].insert(0, str(self.config.DEFAULT_TIMEOUT))
        self.widgets['timeout'].pack(side='left')

        # Колонка с полем ввода растягивается
        frame.columnconfigure(1, weight=1)
    
    def _build_log_section(self):
        """Построение секции отображения логов"""
        frame = tk.Frame(self.root, bg=self.styles['bg'])
        frame.pack(padx=20, pady=10, fill='both', expand=True)
        
        tk.Label(
            frame,
            text="Лог тестирования:",
            font=self.styles['font_bold'],
            bg=self.styles['bg'],
            fg=self.styles['fg']
        ).pack(anchor='w', pady=(0, 5))
        
        # Полоса прокрутки
        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side='right', fill='y')
        
        self.widgets['log'] = tk.Text(
            frame,
            height=15,
            state='disabled',
            wrap='word',
            bg='#1e1e1e',
            fg='#d4d4d4',
            font=('Consolas', 9),
            yscrollcommand=scrollbar.set
        )
        self.widgets['log'].pack(fill='both', expand=True)
        scrollbar.config(command=self.widgets['log'].yview)
    
    def _build_status_section(self):
        """Построение секции отображения статуса"""
        self.widgets['status'] = tk.Label(
            self.root,
            text="Готов к запуску",
            font=self.styles['font_bold'],
            bg=self.styles['bg'],
            fg=self.styles['fg'],
            pady=10
        )
        self.widgets['status'].pack()
    
    def _build_controls(self):
        """Построение кнопок управления"""
        frame = tk.Frame(self.root, bg=self.styles['bg'])
        frame.pack(pady=15)
        
        self.widgets['start_btn'] = tk.Button(
            frame,
            text="▶ Запустить тест",
            command=self._on_start,
            bg=self.styles['success'],
            fg=self.styles['button_fg'],
            font=self.styles['font_bold'],
            width=20,
            cursor='hand2',
            relief='flat',
            padx=10,
            pady=8
        )
        self.widgets['start_btn'].pack()
    
    # -------------------------------------------------------------------------
    # Обработчики событий
    # -------------------------------------------------------------------------
    
    def _bind_clipboard(self, entry: tk.Entry):
        """Привязка горячих клавиш и контекстного меню к полю ввода"""

        def _cut(e=None):
            try:
                if entry.selection_present():
                    entry.event_generate('<<Cut>>')
            except Exception:
                pass
            return 'break'

        def _copy(e=None):
            try:
                if entry.selection_present():
                    entry.event_generate('<<Copy>>')
            except Exception:
                pass
            return 'break'

        def _paste(e=None):
            try:
                entry.event_generate('<<Paste>>')
            except Exception:
                pass
            return 'break'

        def _select_all(e=None):
            entry.select_range(0, 'end')
            entry.icursor('end')
            return 'break'

        # Горячие клавиши
        entry.bind('<Control-c>', _copy)
        entry.bind('<Control-C>', _copy)
        entry.bind('<Control-v>', _paste)
        entry.bind('<Control-V>', _paste)
        entry.bind('<Control-x>', _cut)
        entry.bind('<Control-X>', _cut)
        entry.bind('<Control-a>', _select_all)
        entry.bind('<Control-A>', _select_all)

        # Контекстное меню по правой кнопке
        ctx = tk.Menu(self.root, tearoff=0,
                      bg=self.styles['input_bg'], fg=self.styles['fg'],
                      activebackground=self.styles['button_bg'],
                      activeforeground=self.styles['button_fg'],
                      font=self.styles['font'])
        ctx.add_command(label="Вырезать",   command=_cut)
        ctx.add_command(label="Копировать", command=_copy)
        ctx.add_command(label="Вставить",   command=_paste)
        ctx.add_separator()
        ctx.add_command(label="Выделить всё", command=_select_all)

        def _show_ctx(event):
            entry.focus_set()
            ctx.tk_popup(event.x_root, event.y_root)

        entry.bind('<Button-3>', _show_ctx)   # Windows / Linux
        entry.bind('<Button-2>', _show_ctx)   # macOS (правая кнопка)

    def _load_url_history(self) -> List[str]:
        """Загрузка истории URL из файла"""
        try:
            history_path = self._get_base_dir() / URL_HISTORY_FILE
            if history_path.exists():
                with open(history_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
        except Exception:
            pass
        return []

    def _save_url_history(self):
        """Сохранение истории URL в файл"""
        try:
            history_path = self._get_base_dir() / URL_HISTORY_FILE
            with open(history_path, 'w', encoding='utf-8') as f:
                json.dump(self.url_history, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _add_to_history(self, url: str):
        """Добавление URL в историю (дедупликация + ограничение размера)"""
        if url in self.url_history:
            self.url_history.remove(url)
        self.url_history.insert(0, url)
        self.url_history = self.url_history[:URL_HISTORY_MAX]
        self._save_url_history()

    def _browse_file(self):
        """Открытие браузера файлов"""
        path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if path:
            self.widgets['file_entry'].delete(0, tk.END)
            self.widgets['file_entry'].insert(0, path)
    
    def _on_start(self):
        """Обработка нажатия кнопки запуска"""
        if self.is_running:
            return
        
        try:
            file_path = self.widgets['file_entry'].get().strip()
            attempts = int(self.widgets['attempts'].get())
            timeout = int(self.widgets['timeout'].get())
            test_url = self.widgets['url_combo'].get().strip()
            
            if not file_path:
                messagebox.showerror("Ошибка", "Пожалуйста, выберите файл прокси")
                return
            
            if not test_url:
                messagebox.showerror("Ошибка", "Пожалуйста, укажите URL для тестирования")
                return

            if not test_url.startswith(("http://", "https://")):
                messagebox.showerror("Ошибка", "URL должен начинаться с http:// или https://")
                return
            
            if attempts <= 0 or timeout <= 0:
                messagebox.showerror("Ошибка", "Попытки и таймаут должны быть положительными числами")
                return
            
            # Обновление URL в конфигурации
            self.config.TEST_URL = test_url
            self.tester.config.TEST_URL = test_url

            # Сохранение в историю
            self._add_to_history(test_url)
            
            # Сброс состояния
            self._clear_log()
            self.results.clear()
            self.processed_count = 0
            
            # Запуск потока тестирования
            thread = threading.Thread(
                target=self._run_test,
                args=(file_path, attempts, timeout),
                daemon=True
            )
            thread.start()
            
        except ValueError:
            messagebox.showerror("Ошибка", "Попытки и таймаут должны быть целыми числами")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить: {e}")
    
    # -------------------------------------------------------------------------
    # Основная логика тестирования
    # -------------------------------------------------------------------------
    
    def _run_test(self, file_path: str, attempts: int, timeout: int):
        """Основной процесс тестирования (выполняется в отдельном потоке)"""
        self.is_running = True
        self._update_button_state(False, "⏳ Тестирование...")
        
        try:
            # Создание выходной директории с временной меткой
            output_dir = self._create_output_dir()
            log_path = output_dir / self.config.LOG_FILENAME
            csv_path = output_dir / self.config.CSV_FILENAME
            
            self._log(f"📁 Директория результатов: {output_dir}\n")
            self._log(f"🌐 Тестовый URL: {self.config.TEST_URL}\n")
            
            # Загрузка прокси
            proxies = self._load_proxies(file_path)
            if not proxies:
                self._log("❌ В файле не найдено прокси")
                return
            
            self.total_proxies = len(proxies)
            self._update_status(f"Тестирование 0/{self.total_proxies}")
            
            # Заполнение очереди
            for proxy in proxies:
                self.proxy_queue.put(proxy)
            
            # Открытие лог-файла
            self.log_file = open(log_path, 'w', encoding='utf-8')
            
            # Запуск рабочих потоков
            num_workers = min(self.config.MAX_WORKERS, self.total_proxies)
            self._log(f"🚀 Запуск {num_workers} рабочих потоков для {self.total_proxies} прокси\n")
            
            workers = []
            for _ in range(num_workers):
                t = threading.Thread(
                    target=self._worker,
                    args=(attempts, timeout),
                    daemon=True
                )
                t.start()
                workers.append(t)
            
            # Ожидание завершения
            self.proxy_queue.join()
            
            # Генерация статистики и сохранение
            self._finalize(output_dir, csv_path)
            
        except FileNotFoundError:
            self._log(f"❌ Файл не найден: {file_path}")
            self._update_status("❌ Файл не найден")
        except Exception as e:
            self._log(f"❌ Критическая ошибка: {e.__class__.__name__}: {e}")
            self._update_status(f"❌ Ошибка: {e.__class__.__name__}")
        finally:
            if self.log_file:
                self.log_file.close()
                self.log_file = None
            self.is_running = False
            self._update_button_state(True, "▶ Запустить тест")
    
    def _worker(self, attempts: int, timeout: int):
        """Рабочий поток, который обрабатывает прокси из очереди"""
        while True:
            try:
                proxy = self.proxy_queue.get(timeout=1)
                
                # Тестирование прокси
                result, log_msg = self.tester.test(proxy, attempts, timeout)
                
                # Сохранение результата
                with self.lock:
                    self.results.append(result)
                    self.processed_count += 1
                    
                    if self.log_file:
                        self.log_file.write(log_msg)
                        self.log_file.flush()
                
                # Обновление GUI
                status_icon = "✅" if result.is_successful else "❌"
                summary = f"[{self.processed_count}/{self.total_proxies}] {status_icon} {proxy}"
                
                if result.is_successful:
                    summary += f" | {result.success_percent:.0f}% | "
                    summary += f"{result.latency_ms:.0f}мс | "
                    summary += f"{result.speed_kbps:.2f} KB/s | "
                    summary += f"{result.ip_classification}"
                
                self._log(summary)
                self._update_status(f"Тестирование {self.processed_count}/{self.total_proxies}")
                
                self.proxy_queue.task_done()
                
            except Empty:
                break
            except Exception as e:
                self._log(f"❌ Ошибка рабочего потока: {e}")
                break
    
    def _finalize(self, output_dir: Path, csv_path: Path):
        """Генерация статистики и сохранение CSV"""
        successful = [r for r in self.results if r.is_successful]
        
        # Расчет статистики
        total_success = len(successful)
        total_failed = self.total_proxies - total_success
        success_rate = (total_success / self.total_proxies * 100) if self.total_proxies else 0
        
        avg_latency = sum(r.latency_ms for r in successful) / total_success if total_success else 0
        avg_speed = sum(r.avg_speed_bps for r in successful) / total_success if total_success else 0
        
        # Классификация
        classifications = defaultdict(int)
        for r in successful:
            classifications[r.ip_classification] += 1
        
        # Форматирование статистики
        stats = f"""
{'=' * 70}
📊 СТАТИСТИКА ТЕСТИРОВАНИЯ
{'=' * 70}
Всего прокси:      {self.total_proxies}
✅ Успешные:       {total_success} ({success_rate:.1f}%)
❌ Неуспешные:     {total_failed} ({100-success_rate:.1f}%)

🏷️  Классификация IP:
   Datacenter:     {classifications.get('Datacenter', 0)}
   Residential:    {classifications.get('Residential', 0)}

⚡ Производительность (только успешные):
   Средняя задержка:    {avg_latency:.0f} мс
   Средняя скорость:    {avg_speed/1024:.2f} KB/s

💾 Результаты сохранены в: {output_dir}
{'=' * 70}
"""
        
        self._log(stats)
        
        if self.log_file:
            self.log_file.write(stats)
        
        # Сохранение CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=asdict(ProxyResult("")).keys())
            writer.writeheader()
            for result in self.results:
                writer.writerow(asdict(result))
        
        self._log(f"\n✅ Все тесты завершены! Результаты сохранены в:\n   📄 {csv_path}")
        self._update_status(f"✅ Завершено | {total_success}/{self.total_proxies} успешных")
    
    # -------------------------------------------------------------------------
    # Вспомогательные функции
    # -------------------------------------------------------------------------
    
    def _create_output_dir(self) -> Path:
        """Создание директории результатов с временной меткой"""
        base_dir = self._get_base_dir()
        
        # Создание главной папки результатов если не существует
        results_folder = base_dir / self.config.OUTPUT_FOLDER
        results_folder.mkdir(exist_ok=True)
        
        # Создание подпапки с временной меткой
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_dir = results_folder / f"session_{timestamp}"
        session_dir.mkdir(exist_ok=True)
        
        return session_dir
    
    def _get_base_dir(self) -> Path:
        """Получение базовой директории (расположение программы)"""
        if getattr(sys, 'frozen', False):
            # Запущено как скомпилированный исполняемый файл
            return Path(sys.executable).parent
        # Запущено как скрипт
        return Path(sys.argv[0]).parent.resolve()
    
    def _load_proxies(self, file_path: str) -> List[str]:
        """Загрузка и валидация списка прокси"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self._log(f"❌ Не удалось загрузить прокси: {e}")
            return []
    
    def _clear_log(self):
        """Очистка отображения логов"""
        self.widgets['log'].config(state='normal')
        self.widgets['log'].delete('1.0', tk.END)
        self.widgets['log'].config(state='disabled')
    
    def _log(self, message: str):
        """Потокобезопасное обновление лога"""
        self.root.after(0, self._update_log, message)
    
    def _update_log(self, message: str):
        """Обновление отображения логов (только из главного потока)"""
        self.widgets['log'].config(state='normal')
        self.widgets['log'].insert(tk.END, message + '\n')
        self.widgets['log'].see(tk.END)
        self.widgets['log'].config(state='disabled')
    
    def _update_status(self, text: str):
        """Потокобезопасное обновление статуса"""
        self.root.after(0, lambda: self.widgets['status'].config(text=text))
    
    def _update_button_state(self, enabled: bool, text: str):
        """Потокобезопасное обновление состояния кнопки"""
        state = 'normal' if enabled else 'disabled'
        self.root.after(0, lambda: self.widgets['start_btn'].config(state=state, text=text))


# =============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# =============================================================================

def main():
    """Точка входа приложения"""
    root = tk.Tk()
    app = ProxyCheckerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()