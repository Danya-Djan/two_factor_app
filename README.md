# Web-сервис настройки 2FA

Веб-интерфейс для настройки двухфакторной аутентификации на удалённом сервере. Сервис подключается к серверу по SSH, запускает команду google-authenticator и проводит пользователя через процесс настройки 2FA с генерацией QR-кода и кодов восстановления.

## Структура проекта 

## Установка

1. **Клонируйте репозиторий:**

   ```bash
   git clone https://github.com/Danya-Djan/two_factor_app.git
   ```

2. **Установите зависимости:**
   ```bash
   pip install -r requirements.txt
   ```

## Настройка


1. **Создайте systemd сервис:**
   
   Создайте файл `/etc/systemd/system/twofactor.service`:
   ```ini
   [Unit]
   Description=2FA Setup Web Service
   After=network.target

   [Service] 
   WorkingDirectory=/path/to/project
   Environment="PATH=/path/to/project/venv/bin"
   ExecStart=/path/to/project/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000

   [Install]
   WantedBy=multi-user.target
   ```

2. **Активируйте и запустите сервис:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable twofactor
   sudo systemctl start twofactor
   ```

## Запуск в контейнере

```bash
docker-compose -f docker-compose.yml up --build
```

## Использование

1. Откройте браузер и перейдите по адресу `http://your-server:8000/login`
2. Введите имя пользователя и пароль для SSH-подключения
3. Отсканируйте QR-код с помощью приложения Authenticator
4. Введите код подтверждения из приложения
5. Сохраните показанные коды восстановления в надёжном месте

## Мониторинг

**Просмотр логов:**
```bash
sudo journalctl -u twofactor -f
```

**Проверка статуса:**
```bash
sudo systemctl status twofactor
```

## Разработка

Для локальной разработки:
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## Поддержка

При возникновении проблем:
1. Проверьте логи systemd
2. Убедитесь в доступности SSH-подключения
3. Проверьте права доступа к файлам
4. Убедитесь, что все зависимости установлены корректно