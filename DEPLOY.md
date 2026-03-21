# 🚀 ShadowTalk — Полный гайд по запуску

## Архитектура
```
frontend/index.html  →  backend (Railway)  →  PostgreSQL (Railway)
       ↕ WebSocket (Socket.io realtime)
```

---

## ШАГ 1 — Деплой бэкенда на Railway

### 1.1 Подготовка GitHub репозитория
1. Создай аккаунт на **github.com**
2. Создай новый репозиторий: `shadowtalk-backend`
3. Загрузи папку `backend/` в репозиторий:
   - `src/index.js`
   - `package.json`
   - `railway.toml`
   - `.env.example`

### 1.2 Railway
1. Зайди на **railway.app** → Sign up (можно через GitHub)
2. **New Project** → **Deploy from GitHub repo** → выбери `shadowtalk-backend`
3. Railway автоматически определит Node.js и запустит `npm start`

### 1.3 Добавь PostgreSQL
1. В проекте Railway нажми **+ New** → **Database** → **Add PostgreSQL**
2. Кликни на PostgreSQL сервис → **Variables**
3. Скопируй значение `DATABASE_URL` — Railway автоматически добавит его в бэкенд

### 1.4 Переменные окружения
В Railway → твой бэкенд сервис → **Variables** → добавь:
```
JWT_SECRET=придумай-длинную-случайную-строку-минимум-32-символа
NODE_ENV=production
CLIENT_URL=*
```
> `CLIENT_URL=*` разрешает запросы со всех адресов. После деплоя фронтенда замени на его URL.

### 1.5 Получи URL бэкенда
1. Railway → твой сервис → **Settings** → **Networking** → **Generate Domain**
2. Скопируй URL вида: `https://shadowtalk-backend-production.up.railway.app`
3. Проверь: открой `https://твой-url/health` — должно вернуть `{"status":"ok",...}`

---

## ШАГ 2 — Деплой фронтенда (бесплатно, 30 секунд)

### Вариант A: Netlify Drop (самый быстрый)
1. Открой **app.netlify.com/drop**
2. Перетащи файл `frontend/index.html` прямо в браузер
3. Получи URL типа `https://funny-name-123.netlify.app`

### Вариант B: Vercel
1. Создай GitHub репо `shadowtalk-frontend`, загрузи `index.html`
2. **vercel.com** → New Project → импортируй репо → Deploy
3. Получи URL типа `https://shadowtalk-frontend.vercel.app`

### Вариант C: GitHub Pages (бесплатно навсегда)
1. Создай репо `shadowtalk`
2. Загрузи `frontend/index.html` как `index.html` в корень
3. Settings → Pages → Branch: main → Save
4. URL: `https://твой-ник.github.io/shadowtalk`

---

## ШАГ 3 — Первый запуск

1. Открой фронтенд в браузере
2. Появится экран **"Backend URL"**
3. Вставь URL своего Railway бэкенда
4. Нажми **Connect**
5. Создай аккаунт (никнейм + пароль, без email/телефона)
6. **Готово!** Поделись ссылкой с друзьями

---

## ШАГ 4 — Поделись с друзьями

Друг открывает твою ссылку:
- Первый раз — вводит URL бэкенда (сохраняется в браузере)
- Регистрируется со своим никнеймом
- Ищет тебя по @username
- Пишет — ты получаешь сообщение **мгновенно** через WebSocket

---

## Что работает прямо сейчас

- ✅ Регистрация без телефона/email
- ✅ Вход по username + пароль  
- ✅ Реальные чаты через Socket.io WebSocket
- ✅ Поиск людей по @username (как в Telegram)
- ✅ Онлайн-статусы в реальном времени
- ✅ Индикатор "печатает..."
- ✅ Счётчики непрочитанных
- ✅ Все данные в PostgreSQL
- ✅ JWT авторизация

---

## Следующие шаги (roadmap)

| Фича | Сложность | Описание |
|------|-----------|----------|
| Группы | Средняя | Создание групп, роли |
| Медиафайлы | Средняя | Railway Volumes / S3 |
| Push-уведомления | Средняя | Service Worker + Web Push |
| Голосовые сообщения | Средняя | MediaRecorder API |
| Видеозвонки | Высокая | WebRTC + STUN/TURN |
| E2E шифрование | Высокая | libsodium / Signal Protocol |
| PWA / мобилка | Средняя | manifest.json + Service Worker |

---

## Лимиты Railway (бесплатный план)
- $5 кредитов в месяц (хватит на ~500 часов работы)
- PostgreSQL: 1 GB
- После исчерпания лимита — подними на $5/мес Hobby план

## Файлы
```
backend/
  src/index.js      ← весь сервер (Express + Socket.io)
  package.json      ← зависимости
  railway.toml      ← конфиг Railway
  .env.example      ← переменные окружения

frontend/
  index.html        ← весь фронтенд (один файл)
```
