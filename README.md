### Rust eBPF Firewall (POC)

#### Описание

Демонстрация возможности написания eBPF Firewall на Rust, оно же Proof Of Concept.

Поддерживает IPv4/v6, TCP/UDP.

#### Сборка и запуск

1. Установить [Rust](https://www.rust-lang.org/learn/get-started)
2. `rustup default stable`
3. `rustup toolchain add nightly`
4. `rustup component add rust-src --toolchain nightly`
5. `cargo install cargo-generate`
6. `cargo install bpf-linker`
7. `cargo install bindgen-cli`
8. `make build` - сборка проекта.
9. `make run` - запуск проекта. Если в `Makefile` изменить `RUST_LOG=info` на `RUST_LOG=debug` то будект показан весь перехватываемый траффик.


#### Описание настроек
Настроки находятся в `cobtrib/settings.yaml`.

`interfaces` - Сетевые интерфейсы с которыми работаем.

`input / output` соответственно отвечают за то, какой тип трафика на указанном интерфейсе обрабатываем.

Firewall работает **только** в режиме дропа пакетов.

Секции `v4/v6` отвечают соответственно за `IPv4` и `IPv6`

`input / output` - за тип траффика, входящий / исходящий.

`addresses / ports` - списки портов которые блокируем.