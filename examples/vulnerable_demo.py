"""Учебный образец с намеренными дефектами — материал для проверки анализатора.

ЭТОТ ФАЙЛ НЕ ПРЕДНАЗНАЧЕН ДЛЯ ЗАПУСКА. Он существует только для того, чтобы
показать, что именно находит aegis, и служит эталоном при доработке правил.

Запуск проверки::

    python -m aegis examples/vulnerable_demo.py
"""

import hashlib
import os
import pickle
import random
import re
import shlex
import sqlite3
import subprocess
import tempfile

import requests
from flask import Flask, request

app = Flask(__name__)

# Секрет прямо в исходнике: любой, у кого есть доступ к репозиторию, его видит.
API_KEY = "sk_live_9fKq2XmPz7Ld4Wn8"
DB_PASSWORD = "admin"


@app.route("/ping")
def ping():
    """Данные из запроса попадают в оболочку без экранирования."""
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()


@app.route("/ping-safe")
def ping_safe():
    """Тот же код, но с экранированием — находки быть не должно."""
    host = request.args.get("host")
    return os.popen("ping -c 1 " + shlex.quote(host)).read()


@app.route("/archive")
def archive():
    """Имя файла из запроса задаёт путь: возможен выход за пределы каталога."""
    name = request.args["name"]
    with open("/var/data/" + name, "rb") as handle:
        return handle.read()


@app.route("/user")
def user():
    """Значение подставляется в текст запроса вместо параметра."""
    connection = sqlite3.connect("app.db")
    uid = request.args.get("id")
    rows = connection.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()
    return str(rows)


@app.route("/restore", methods=["POST"])
def restore():
    """Десериализация данных от клиента позволяет выполнить произвольный код."""
    return str(pickle.loads(request.data))


@app.route("/fetch")
def fetch():
    """Адрес запроса задаёт пользователь — сервер сходит куда угодно."""
    return requests.get(request.args["url"], verify=False).text


def run_backup(destination):
    """Аргумент приходит из обработчика ниже — грязь передаётся через вызов."""
    subprocess.run("tar czf backup.tgz " + destination, shell=True)


@app.route("/backup")
def backup():
    return run_backup(request.args["dir"])


def hash_password(password):
    """MD5 подбирается перебором за минуты."""
    return hashlib.md5(password.encode()).hexdigest()


def new_session_token():
    """random предсказуем: зная несколько значений, следующее вычисляется."""
    session_token = random.getrandbits(64)
    return str(session_token)


def check_password(supplied, stored_password):
    """Сравнение прекращается на первом различии — пароль подбирается по времени."""
    return supplied == stored_password


def parse_version(text):
    """Если совпадения нет, re.match вернёт None, и .group() упадёт."""
    match = re.match(r"v(\d+)", text)
    return match.group(1)


def collect(items, seen=[]):
    """Список создаётся один раз и накапливает данные между вызовами."""
    seen.extend(items)
    return seen


def write_temp(data):
    path = tempfile.mktemp()
    with open(path, "w") as handle:
        handle.write(data)
    os.chmod(path, 0o777)
    return path


def load_config(path):
    try:
        with open(path) as handle:
            return handle.read()
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
