# CloudInitWin

This project provides a Windows implementation of CloudInit intended for use with Proxmox. For this reason, only a subset of the functionality of CloudInit is supported.
The application is a Windows service which runs idempotently - though uninstalling and removing the cloudinit drive is recommended after provisioning a VM.

Tested on Windows 11 Professional.

## Building

To simply make a debug build, run:

        cargo build

To package for use, run:

        cargo build --release
        ./package.ps1

Which will create `cloudinitwin.zip` for use on a VM

## Usage

1. Create a Windows VM to use as a template
1. Copy the package to the VM
1. Install CloudInitWin using the `install.ps1` script

    (Note that this also installs Windows OpenSSH to support some cloudinit options)

1. The VM may be used as a template at this stage, OR you may wish to fully generalize the install using `sysprep` with the provided `Unattend.xml` file with the `sysprep.ps1` script.

The default user is `Admin`.

## Uninstallation

Run the `uninstall.ps1` script, or simply delete the `CloudInitWin` service and the `%PROGRAMFILES%/CloudInitWin` directory

## Contributing

Contributions are welcome! Please feel free to:

- Submit pull requests for bug fixes or new features
- Open issues to report bugs or suggest improvements
- Provide feedback on the project's functionality and documentation