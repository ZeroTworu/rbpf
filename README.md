### Rust eBPF Firewall (POC)

#### Описание:

Демонстрация возможности написания eBPF Firewall на Rust, оно же Proof Of Concept.

* Поддерживает `IP` `v4`/`v6`, `TCP`/`UDP`.
* Для обработки исходящих соединений используется `Classifiers`. 
* Для обработки входящих - `eXpress Data Path`.
* Логирование целиком в `userspace`.
* HTTP REST API для управления фаерволом.
* Web UI.
* Поддержка архитектур: `x86_64`, `armv7`, `aarch64`.

#### Структура проекта:
* `rbpf-common` - Общие структуры, которыми компоненты обмениваются через `BPF_MAPS` user space <-> eBPF (kernel space) или control Unix Socket. 


* `rbpf-ebpf` - eBPF модуль загружаемый в ядро.


* `rbpf-http` - HTTP REST API сервер, так как `rbpf-loader` запускается из-под `root` что бы иметь возможность загрузить eBPF модуль, то в самом
`rbpf-loader` мы не можем держать HTTP REST API сервер. Запускать HTTP сервер от `root` - крайне плохая затея с точки зрения безопасности.


* `rbpf-loader`- Модуль загружающий `rbpf-ebpf`, и обеспечивающий связь между user space и eBPF (kernel space). Может создавать Unix Socket для приёма команд.

* `rbpf-ui` - WebUI (Single Page Application написанное на Vue.js v3). Служит для вывода информации и управления eBPF модулем. 

#### Принцип работы:

##### Передача информации из ядра в браузер
* `(eBPF module in kernel`) -> `(RingBuf)` -> `(loader module in root space)` -> `(unix socket)` -> `(HTTP module in user space)` -> `(web socket)` -> `(browser)`

##### Передача информации из браузера в ядро
* `(browser)` -> `(HTTP request)` -> `(HTTP module in user space)` -> `(unix socket)` -> `(loader module in root space)` -> `(BPF HASH MAP)` -> `(eBPF module in kernel`)

[Сборка и установка зависимостей](docs/build.md)


[Описание HTTP модуля](docs/http.md)


[Описание Loader модуля](docs/loader.md)


[Описание Правил фильтрации](docs/rules.md)

[Скрины](docs/screens.md)
