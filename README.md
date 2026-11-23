# enzimOS Installer Backend

This is the backend used by enzimOS installation media. It validates installation
plans, prepares storage, installs packages, configures the target system and
writes its boot entries. The graphical installer lives in a separate repository.
Text, serial and unattended entry points are included here.

## How installation works

The live installer exposes network, partition and installation requests to the
graphical frontend. It validates the submitted plan and checks the installation
media before starting work. A separate package worker handles the package
transaction. The backend also provides the `boot-menu` command used to refresh
the installed boot entries.

Whole-disk installation uses `systemd-repart` to create a new partition table
from the reviewed plan. Alongside installation uses `sfdisk` so it can place
new partitions at the exact offsets the user reviewed. The backend checks
the resulting layout before it continues.

When the offline app fleet is selected, the installer sets system defaults for
the browser, calendar, documents, audio, images and video based on the apps it
installed. Individual users can change those defaults in their own session.

## Repository layout

- [`src/`](src/) contains the backend and package worker.
- [`live/`](live/) contains the live-media launcher, systemd services and
  initramfs configuration.
- [`boot/`](boot/) contains the boot entry selector, artwork and refresh units.
- [`packaging/rust/`](packaging/rust/) contains the runtime package recipe and
  the `ui-install`, `ui-network` and `ui-partition` wrappers used by the frontend.

The live image needs the installer runtime package before it starts the
graphical frontend.

## Build and test

Requires Linux, Rust 1.95 or newer, and a C compiler for the boot selector test.

```sh
cargo build --release --locked
cargo test --locked
```

The Rust tests use fixture plans, temporary directories, private IPC and test
processes. To run the EFI boot selector parser test on the host:

```sh
test_dir=$(mktemp -d)
cc -fshort-wchar tests/select-entry-test.c -o "$test_dir/select-entry-test"
"$test_dir/select-entry-test"
rm -r "$test_dir"
```

Run actual installation commands from live media in a disposable VM with its
own disks. Use separate VM runs to validate whole-disk and alongside installs,
boot selection, encryption and recovery.

## License

[MIT](LICENSE)
