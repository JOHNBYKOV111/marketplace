Корпоративный Маркетплейс
Проект представляет собой высоконагруженную, отказоустойчивую микросервисную платформу электронной коммерции (E-Commerce Marketplace). Архитектура построена на принципах эшелонированной обороны,
строгого разделения ответственности (CQRS) и гарантирует выживаемость бизнес-функций магазина при масштабных авариях инфраструктуры (сетевой деградации, падении смежных сервисов или баз данных).
api-gateway — единая точка входа для внешних клиентов, осуществляющая первичную маршрутизацию трафика и балансировку.
auth-service — ключевой сервис безопасности, отвечающий за регистрацию пользователей, управление сессиями, двухфакторную аутентификацию (MFA), генерацию, валидацию и ротацию криптографических JWT-токенов.
user-service — сервис ведения профилей клиентов маркетплейса, управления ролями (RBAC) и ведения журналов корпоративного аудита (Audit Trail).
Служебные микросервисы — каркас бизнес-логики: cart-service (корзина), order-service (заказы), payment-service (платежный шлюз) и notification-service (уведомления).

Основной функционал:
1. Управление пользователями и профилями (User Management). Регистрация и профилирование: Создание учетных записей, управление персональными данными (имя, фамилия, телефон) через user-service.
High-Load кэширование профилей: Мгновенная выдача данных горячих профилей из Redis по паттерну Cache-Aside со скоростью 5234 RPS.
Автоматическая инвалидация: Принудительный сброс закэшированного профиля в Redis при изменении данных или блокировке для защиты от чтения устаревших данных (Stale Data).
Мягкое удаление (Soft Delete): Маркировка учетных записей как удаленных без физического стирания строк в БД на случай оспаривания транзакций. 

2. Безопасность и Авторизация (Auth Core & RBAC)
Двухфакторная аутентификация (MFA): Поддержка одноразовых кодов (TOTP/Google Authenticator) и резервных кодов восстановления с защитой от гонок (Race Conditions) при одновременной активации.
Генерация и разбор JWT: Использование криптографических пар ключей (JWKS) для подписи и проверки токенов доступа.
Многосессионный режим: Возможность одновременного входа с разных устройств (ПК, телефон) с контролем лимита активных сессий.
Ротация рефреш-токенов (Refresh Token Rotation): Механизм защиты от кражи сессии — при повторном использовании старого Refresh-токена система автоматически аннулирует всю цепочку сессий пользователя.
Черный список токенов (Token Blacklisting): Атомарный отзыв токенов в Redis с поддержкой времени жизни (TTL) при логауте.

3. Корпоративный контроль и Защита данных (Compliance & Security)
Соответствие стандарту GDPR: Полное физическое уничтожение всех данных клиента по требованию о забвении (GDPR Delete) с каскадным отзывом токенов и очисткой баз данных обоих сервисов.
Анонимизация ПДн: Хранение и индексация критических данных (email, телефон) строго в виде криптографических слепков email_hash и phone_hash.
Журнал аудита действий (Audit Trail): Логирование критических действий (вход, смена пароля, блокировки) в СУБД с гибкой системой SQL-фильтров для службы безопасности.
Автоматическая ротация логов (Cleanup Policy): Фоновое удаление старых логов аудита, чей возраст превысил установленный лимит дней, для экономии дискового пространства.
Защита от SQL-инъекций: Встроенная фильтрация и экранирование входящих параметров (поля ввода, UUID, заголовки) от хакерских атак.

4. Отказоустойчивость и Инженерия хаоса (Resilience Core)
Изоляция аварий (Circuit Breaker): Микросекундное автоматическое отключение шлюзов к деградирующему сервису в режиме Fast-Fail (10 000+ RPS), защищающее Event Loop от зависания.
Плавная деградация (Graceful Degradation): Выдача резервных фоллбэк-данных (заглушек) клиенту в случае полного падения сети, сохраняя интерфейс магазина работоспособным.
Инжекция сбоев (Chaos Middleware): Кастомная ASGI-мидлварь для детерминированной симуляции таймаутов и 503 ошибок на стороне auth-service для проведения учений.

5. Инфраструктура и Интеграция (Infrastructure)
Асинхронный транспорт: Оптимизированный HTTP-клиент на httpx.AsyncClient с постоянным удержанием Keep-Alive сессий и расширенным пулом до 500 соединений.
Синхронный межсервисный обмен: Высокоскоростные каналы gRPC для мгновенного обмена данными между внутренними сервисами платформы.
Асинхронная шина событий (Apache Kafka): Отправка доменных событий (например, «пользователь зарегистрирован») в брокер сообщений с буферизацией на случай его отказа.
Оркестрация и Мониторинг: Готовые эндпоинты Liveness/Readiness для Kubernetes и сквозная выгрузка метрик производительности в формате Prometheus.

6. Тестирование и Контроль качества (Quality Assurance & Chaos Engineering)
Комплексная пирамида тестирования: Кодовая база полностью покрыта многоуровневой матрицей проверок (Unit, API Integration, E2E, Resilience) из 300+ автоматизированных сценариев.
Автоматизация верификации транзакций: Интеграционные тесты СУБД (PostgreSQL) автоматически накатывают миграции Alembic и проверяют атомарность SQL-запросов и транзакций при создании и мутации данных.
Изолированный синтаксический аудит: Встроенные механизмы валидации позволяют проводить сквозную проверку синтаксиса и корректности импортов всех инфраструктурных фикстур и фабрик объектов.
Защита от деградации тестов: Тестовые сценарии оснащены автоматическими заградотрядами (Health Checks), блокирующими ложные срабатывания при временном отключении сетевых интерфейсов.

Архитектурные паттерны:
Resilience & Availability
Circuit Breaker - три состояния (CLOSED / OPEN / HALF_OPEN), порог ошибок, recovery timeout, trial requests, success threshold
Fast-Fail / Fast-Path - синхронная проверка cb.is_open до await, чтобы избежать asyncio context switch при 1000+ RPS
Graceful Degradation - fallback данные ({user_id}@unknown.com, is_active=True, is_email_verified=False) вместо ошибок
Fallback API - CircuitBreaker.call_with_fallback(primary, fallback)
Bulkhead / Connection Pool Limits - httpx Limits (500 max / 200 keepalive), SQLAlchemy pool_size + max_overflow
Health Checks (Liveness/Readiness) - /health эндпоинты для Kubernetes
Timeout Budget - httpx.Timeout(connect=2s, read=timeout, write=timeout, pool=2s)

Caching
Cache-Aside - Redis, при miss - источник, запись в кэш
Cache Stampede Protection (Thundering Herd) - asyncio.Lock per-user, double-checked locking
Never Cache Failures - fallback'и и ошибки не кэшируются (anti-poisoning)
Cache Invalidation - при block / unblock / delete / update - redis.delete(key)
TTL - _USER_INFO_CACHE_TTL = 300s

Transport & CQRS
CQRS на transport layer - GET через CB, POST/PUT/DELETE bypass CB
Shared Connection Pool - единый httpx.AsyncClient на весь сервис
Keep-Alive - keepalive_expiry=30s
Idempotent Conflict Resolution - /internal/user/create при 409 возвращает существующий user_id в body
Fire-and-Forget Notifications - _notify_auth_* методы никогда не пробрасывают ошибки
Domain Exceptions - AuthServiceError, AuthServiceUnavailableError, CircuitBreakerOpenError - изоляция от инфраструктуры

Security
JWT - с JWKS-подписью
Refresh Token Rotation - при повторном использовании старого токена вся цепочка сессий аннулируется
Token Blacklist - атомарный отзыв в Redis с TTL
TOTP/MFA - Google Authenticator + backup codes
RBAC - роли, разрешения, user_roles
Pepper (SECRET_PEPPER) - добавляется к паролю до bcrypt
Email/Phone Hash - SHA-256 слепки вместо plaintext
Email normalization - +tag отрезается перед хэшированием
Internal API Key - X-Internal-API-Key для межсервисных вызовов
IP Whitelist - INTERNAL_ALLOWED_IPS для internal endpoints
Rate Limiting - на auth-service, защита от burst
Production Guard - fault injection → 404 при ENVIRONMENT=production
SQL injection defense - Pydantic/UUID валидация + SQLAlchemy parameterized queries

Compliance
GDPR Delete - каскадное удаление в обоих сервисах + revoke токенов
Soft Delete - is_deleted + deleted_at, физическое стирание позже
Audit Trail - логирование критических действий в СУБД
Log Cleanup Policy - фоновое удаление старых аудитов

Chaos Engineering
Application-Level Fault Injection - /internal/test/faults/503, /timeout, /reset, /status
Multi-Worker Fault Sync - синхронизация состояния faults между воркерами Gunicorn
Deterministic Chaos Middleware - ASGI middleware для симуляции таймаутов и 503

Infrastructure
CQRS-Transport
Singleton DB Engines - в тестах не пересоздаются на каждый запрос
Toxiproxy Integration - network-level fault injection (latency, timeout, connection reset)
Kafka Event Bus - доменные события с буферизацией
gRPC - внутренний межсервисный обмен

Testing Patterns
Test Pyramid - unit / integration / e2e / resilience
No Mocks Policy - реальные HTTP, Redis, PostgreSQL, CircuitBreaker
Dynamic UUID Resolution - резолвинг реального UUID из БД, не хардкод
Dual-DB AUTOCOMMIT Seeding - прямая запись в обе БД в обход ОРМ-изоляции
Cross-Module Cool-Down - pytest_runtest_teardown с паузой между файлами
Cold-Start Warmup - 10 сек на первый тест для прогрева PostgreSQL
Isolation per Test - _force_clean_before_each_test (faults + Redis + CB + user)
Guaranteed Cleanup with Verification - fault_reset_all_verified() с retry
Session-Scoped Credentials - один email на всю сессию E2E
Consistent UUID Across DBs - _find_existing_user_id перед созданием
Idempotent Seeding - ON CONFLICT (email) DO NOTHING / ON CONFLICT (email_hash) DO UPDATE
Property-Based Testing - test_1000rps, test_burst_500, test_concurrent_100

Observability
Structured JSON Logging - trace_id, duration_ms, status_code
Slow Query Detection - event listener SQLAlchemy >200ms
Prometheus Metrics - get_metrics() для CB, business_metrics
Liveness/Readiness - для Kubernetes

Code Architecture
Repository Pattern - UserRepository, AuditRepository, TokenRepository
Service Layer - UserService, AuthService, TokenService
Dependency Injection - FastAPI Depends
Async Context Manager - для клиентов, сессий, транзакций
Immutable Config - @dataclass(frozen=True) для CircuitBreakerConfig

ТЕСТОВОЕ ПОКРЫТИЕ: 
Auth-Service
integration 126 passed. Проверка транспортного слоя с юзер сервисом.
middlewares and core 187 passed. Интеграционные тесты ядра и глобальной обработки запросов.Проверка надежности фундаментальной изоляции платформы.
repositories 170 passed. Интеграционные тесты слоя доступа к данным.
services 185 passed. Интеграционные тесты слоя инфраструктурных сервисов и интеграций.
resilience 74 passed. Хаос-тесты стейт-машины, отказоустойчивости и стресс-тесты под экстремальной нагрузкой.
unit 1611 passed. Логика и алгоритмы «чистого» кода сервиса в абсолютной изоляции от внешнего мира.
Итого: 2353 passed.

User-Service
e2e 46 passed. Сквозные интеграционные тесты реальной бизнес-логики.
integration 158 passed. Реальная надежность внутренних компонентов, баз данных и безопасности в изоляции одного сервиса.
circuit 18 passed. Точность и отказоустойчивость ядра стейт-машины предохранителя (CircuitBreaker) и алгоритмов ограничения трафика (Rate Limiting) на стыке сервисов.
degradation 16 passed. Интеграционные хаос-тесты сценариев контролируемой деградации (Controlled Degradation & Fallback Integration Tests). Проверка бизнес-контрактов выживаемости системы.
load 22 passed. Проверка при экстремальном наплыве пользователей.
reliability 10 passed. Проверка строгого архитектурного контракта идемпотентности и консистентности системы при многократных повторных операциях (Retries) в условиях жесткого сбоя.
security 14 passed. Интеграционные тесты безопасности и отказоустойчивости Module 1. Изоляция ошибок авторизации Module 2. Устойчивость к SQL-инъекциям.
unit 138 passed. Модульные тест-кейсы, которые проверяют изолированные Python-классы, Pydantic-схемы и методы бизнес-логики user-service в оперативной памяти без участия реальных баз данных или сети.
Итого: 422 passed.

Запуск проекта: 

Условия для Linux (Ubuntu / Debian / CentOS)
Docker Engine (docker-ce версии 24.0+).
Docker Compose V2 (пакет docker-compose-plugin).
Права доступа: 
Текущий пользователь Linux должен быть добавлен в группу docker (sudo usermod -aG docker $USER), иначе (Permission denied).
Системные лимиты ядра (Тюнинг под нагрузочные тесты):
Тяжелые тесты нагрузки (5234 RPS из кэша и 250+ RPS по сети) упираются в стандартные лимиты ОС Linux на количество открытых файлов и сетевых сокетов.
Перед запуском тестов load необходимо временно расширить лимиты сессии: bash
Увеличиваем лимит дескрипторов файлов (чтобы httpx.AsyncClient не дропал сокеты)
ulimit -n 65535
Сетевые службы:
Системный демон systemd-resolved или локально установленные postgresql.service / redis-server.service остановлены и не занимают порты 5432 и 6379 на сетевом интерфейсе localhost.
Установка зависимостей requirements.txt

Условия для Windows (Windows 10 / 11 Pro или Home)
Аппаратная виртуализация:
BIOS/UEFI процессора должна быть строго включена виртуализация (Intel VT-x или AMD-V).
Компоненты Windows:
Должна быть активирована подсистема WSL2 (Windows Subsystem for Linux 2) и компонент Virtual Machine Platform (Платформа виртуальной машины).
Установлен официальный дистрибутив Ubuntu (22.04 LTS или 24.04 LTS) из Microsoft Store.
Настройка Docker Desktop:
Установлен Docker Desktop для Windows.
В настройках движка должен быть выбран бэкенд на базе WSL2 (Settings -> General -> Use the WSL 2 based engine).
Критически важно:
Включена сквозная интеграция с вашей установленной Ubuntu (Settings -> Resources -> WSL integration -> Включить чекбокс напротив вашей Ubuntu).
Это позволит командам docker внутри консоли Ubuntu беспрепятственно управлять Docker-демоном Windows.
Файловая система (Важно для скорости работы БД):
Папка проекта marketplace должна физически находиться внутри файловой системы Linux.
Или через Docker Desktop сборкой контейнеров.

Стек технологий:
Web Framework:
fastapi==0.104.1
uvicorn[standard]==0.24.0
gunicorn==21.2.0
python-multipart==0.0.6
orjson==3.9.15

API Gateway:
Nginx

Data & Storage:
sqlalchemy==2.0.23
asyncpg==0.29.0
psycopg2-binary==2.9.9
alembic==1.12.1
redis==5.0.1
aioredis==2.0.1
aiosqlite>=0.20.0

Validation & Config:
pydantic==2.5.0
pydantic-settings==2.1.0
python-dotenv==1.0.0
email-validator>=2.0.0

Security & Auth:
PyJWT==2.8.0
cryptography==41.0.7
bcrypt==4.0.1
passlib>=1.7.4
argon2-cffi>=23.1.0
pyotp==2.8.0
qrcode[pil]>=7.4,<8.0

Messaging & Integration:
aiokafka==0.8.1
kafka-python==2.0.2
grpcio>=1.60.0
grpcio-tools>=1.60.0

HTTP Clients:
httpx==0.25.2
aiohttp==3.9.1
tenacity==8.2.3

Utilities:
python-dateutil>=2.8.2

Testing:
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
freezegun==1.5.1
factory-boy==3.3.0

Проект полностью готов к работе.
