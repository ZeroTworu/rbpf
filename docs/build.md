#### Быстрая сборка:
* `./build.sh --build-bin` - Сборка Rust приложения (x86_64).
* `./build.sh --build-bin-armv7` - Сборка Rust приложения (armv7).
* `./build.sh --build-bin-aarch64` - Сборка Rust приложения (aarch64).
    * Для `Debian 12.10.0` под `armhf` и `aarch64` (видимо проблема в debian, а не архитектурах) пришлось выполнить `tc qdisc add dev <IFACE> clsact` (для OUTPUT listener) и `ip link set dev <IFACE> xdp off` (для INPUT listener) иначе листенеры не хотели цепляться к сетевым интерфейсам.
    * Добавил ключи `--fi` и `--fo` для автоматического применения этих комманд при запуске `rbpf_loader` для `input` и `output` интерфейсов соответственно.
------
* `./build.sh --build-bin-zip` - Сборка и упаковка Rust приложения (x86_64).
* `./build.sh --build-bin-zip-armv7` - Сборка и упаковка Rust приложения (armv7).
* `./build.sh --build-bin-zip-aarch64` - Сборка и упаковка Rust приложения (aarch64).

------
* `./build.sh --build-vue` - Сборка WebUI приложения.
* `./build.sh --build-vue-zip` - Сборка и упаковка WebUI приложения.


#### Настройка рабочей среды для разработки:
1. Установить [Rust](https://www.rust-lang.org/learn/get-started)
2. `rustup default stable`
3. `rustup toolchain add nightly`
4. `rustup component add rust-src --toolchain nightly`
5. `cargo install cargo-generate`
6. `cargo install bpf-linker`
7. `cargo install bindgen-cli`

### Xtask
После подготовки рабочей среды вам доступны `cargo xtask`, краткое описание.

* `cargo xtask build-bin <ARCH>` Создание бинарных файлов, доступные архитектуры:
    * `x86_64`
    * `armv7`
    * `aarch64`

* `cargo xtask build-bin-zip <ARCH>` Аналогично предыдущей, только с упаковкой в архиа.

* `cargo xtask build-vue` Генерация WebUI.
* `cargo xtask build-vue-zip` Генерация WebUI и упаковка в архив.
* `cargo xtask prepare` Подготовка дополнительных файлов для упаковки в пакеты.
* `cargo xtask build-pkg <PKG>` Создание установочного пакета, в качестве `<PKG>` доступны:
    * `zst`
    * `deb`
    * `rpm`
