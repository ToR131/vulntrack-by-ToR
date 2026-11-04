# Отчёт по уязвимостям: все активы

Сформирован 2026-11-04. Открыто — критическая: 0, высокая: 4, средняя: 5, низкая: 0. Просрочено по SLA: 4. Устранено: 2.

| ID | Критичность | CVSS | Уязвимость | Где | Статус | Срок |
| --- | --- | --- | --- | --- | --- | --- |
| #2 | Высокая | — | Cross Site Scripting (Reflected) | `https://shop.example.test/search` | Открыта | **2026-10-31 (просрочено на 4 дн.)** |
| #9 | Высокая | 7.5 | Apache 2.4.49 - Path Traversal | `https://shop.example.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` | Открыта | **2026-10-31 (просрочено на 4 дн.)** |
| #11 | Высокая | — | SQL query built with string formatting | `app/db.py:27` | Открыта | **2026-10-31 (просрочено на 4 дн.)** |
| #13 | Высокая | — | Hard-coded API key in source code | `app/config.py:12` | Открыта | **2026-10-31 (просрочено на 4 дн.)** |
| #3 | Средняя | — | Content Security Policy (CSP) Header Not Set | `https://shop.example.test/` | Открыта | 2026-12-30 (осталось 56 дн.) |
| #4 | Средняя | — | Content Security Policy (CSP) Header Not Set | `https://shop.example.test/search` | Открыта | 2026-12-30 (осталось 56 дн.) |
| #5 | Средняя | — | Absence of Anti-CSRF Tokens | `https://shop.example.test/profile/{id}/edit` | Открыта | 2026-12-30 (осталось 56 дн.) |
| #8 | Средняя | — | Git Configuration - Detect | `https://shop.example.test/.git/config` | Открыта | 2026-12-30 (осталось 56 дн.) |
| #12 | Средняя | — | Flask application runs with debug=True | `app/main.py:58` | Открыта | 2026-12-30 (осталось 56 дн.) |

## #2 Cross Site Scripting (Reflected)

- **Критичность:** Высокая
- **Где:** `https://shop.example.test/search`, параметры: q
- **Классификация:** CWE-79
- **Сканеры:** zap
- **Как исправить:** Encode output for the HTML context (use the template engine's auto-escaping), validate input, and add a Content-Security-Policy that forbids inline scripts.

```text
GET https://shop.example.test/search?q=test
Параметр: q
Атака: <script>alert(1);</script>
Признак в ответе: <script>alert(1);</script>
```

## #9 Apache 2.4.49 - Path Traversal

- **Критичность:** Высокая, CVSS 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Где:** `https://shop.example.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`
- **Классификация:** CVE-2021-41773, CWE-22
- **Сканеры:** nuclei
- **Как исправить:** Upgrade Apache HTTP Server to 2.4.51 or later.

```text
Шаблон CVE-2021-41773 сработал на https://shop.example.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
Извлечено: root:x:0:0:root:/root:/bin/bash
Воспроизведение: curl -X 'GET' --path-as-is 'https://shop.example.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'
```

## #11 SQL query built with string formatting

- **Критичность:** Высокая
- **Где:** `app/db.py:27`
- **Классификация:** CWE-89
- **Сканеры:** semgrep-oss
- **Как исправить:** Pass values as query parameters: cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,)).

```text
app/db.py:27
cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")
```

## #13 Hard-coded API key in source code

- **Критичность:** Высокая
- **Где:** `app/config.py:12`
- **Классификация:** CWE-798
- **Сканеры:** semgrep-oss
- **Как исправить:** Move the key to a secrets vault or environment variable and rotate the leaked key.

```text
app/config.py:12
PAYMENT_API_KEY = "sk_demo_************************"
```

## #3 Content Security Policy (CSP) Header Not Set

- **Критичность:** Средняя
- **Где:** `https://shop.example.test/`
- **Классификация:** CWE-693
- **Сканеры:** zap
- **Как исправить:** Configure the web server or application to return a Content-Security-Policy header.

```text
GET https://shop.example.test/
```

## #4 Content Security Policy (CSP) Header Not Set

- **Критичность:** Средняя
- **Где:** `https://shop.example.test/search`
- **Классификация:** CWE-693
- **Сканеры:** zap
- **Как исправить:** Configure the web server or application to return a Content-Security-Policy header.

```text
GET https://shop.example.test/search?q=test
```

## #5 Absence of Anti-CSRF Tokens

- **Критичность:** Средняя
- **Где:** `https://shop.example.test/profile/{id}/edit`
- **Классификация:** CWE-352
- **Сканеры:** zap
- **Как исправить:** Add a per-session anti-CSRF token to state-changing forms and set SameSite on the session cookie.

```text
GET https://shop.example.test/profile/1024/edit
Признак в ответе: <form action="/profile/1024/edit" method="post">
```

## #8 Git Configuration - Detect

- **Критичность:** Средняя
- **Где:** `https://shop.example.test/.git/config`
- **Классификация:** CWE-200
- **Сканеры:** nuclei
- **Как исправить:** Deny access to /.git on the web server and keep the directory out of the deployment artifact.

```text
Шаблон git-config сработал на https://shop.example.test/.git/config
Извлечено: [remote "origin"]
Воспроизведение: curl -X 'GET' 'https://shop.example.test/.git/config'
```

## #12 Flask application runs with debug=True

- **Критичность:** Средняя
- **Где:** `app/main.py:58`
- **Классификация:** CWE-489
- **Сканеры:** semgrep-oss
- **Как исправить:** Read the debug flag from configuration and keep it off outside local development.

```text
app/main.py:58
app.run(host="0.0.0.0", debug=True)
```
