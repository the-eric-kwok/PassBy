# PassBy (iOS 9 through 15)

This is a highly customizable iOS/iPadOS Tweak that lets you avoid being asked for passcode when certain conditions are verified.

These safe conditons are determined by the device's connectivity, and include a customizable timeout after which, even if the condition is still true, you will be asked for the passcode/biometrics again.

## Compatibility

- iOS 9 – 15, 64-bit devices (iPhone 5s / iPad mini 2 and newer), iPhone & iPad.
- Jailbreak flavours: builds for both **rootful** (e.g. palera1n rootful) and **rootless** (Dopamine / Fugu15) setups.
- 32-bit (armv7) devices are no longer supported: they cannot run any iOS version this build targets.

## Unlock Options

Auto-unlock can be enabled under these conditions:

- Within a timeframe since last time the device was locked
- Connected to specific WiFi networks
- Connected to specific Bluetooth devices
- Connected to Apple Watch
- Wired Headphones plugged in

It can be chosen whether to enable the bypass upon connection or after the first normal unlock in presence of the condition.

The tweak also allows to automatically dismiss the LockScreen CoverSheet when no notification or media controls are showing.

> The former Flipswitch and Activator integrations have been removed in 2.0 to keep the attack surface small and startup-safe.

## Respring safety

Automatic unlock is gated behind a SpringBoard-ready check (`application:didFinishLaunchingWithOptions:`) plus a lock-screen-UI-ready check before any passcode replay. During the SpringBoard startup window after a respring, PassBy never attempts to unlock — this is what previously soft-bricked iPads on an endless spinner with other iOS 15 ports.

## Security

The main concern people have with this tweak is whether it lowers the device's security, however that depends on the configuration.

The tweak employs AES128 to store both the device passcode and the WiFi networks/BT devices names.

The tweak will also warn users when they try to add an unprotected network to the whitelist:
if an attacker were to set up an open network with an identical name, your phone will connect to it,
thus unlocking itself (if set to do so upon connection).

## Building

Requirements: [Theos](https://theos.dev) at `~/theos` with `iPhoneOS16.5.sdk` in `~/theos/sdks`, and `dpkg` (`brew install dpkg`).

```sh
# rootful package (arm64 + arm64e)
make rootful-package

# rootless package (arm64), for Dopamine / Fugu15
make rootless-package
```

Packages land in `packages/`.
