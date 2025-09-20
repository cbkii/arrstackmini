# Changelog

## [1.0.0] - Unreleased
### Added
- Generated `.arraliases` file during installation with placeholder replacement.
- Version management guide documenting pinned container tags.
- Warnings in the installer summary for broad LAN exposure and default credentials.
- Expanded troubleshooting guide with credential resets and port-forward steps.

### Changed
- Pinned all service images to explicit versions with override support.
- Port-sync helper now prefers localhost authentication bypass and falls back to configured credentials.
- Installer waits longer for Gluetun health and continues with warnings instead of aborting.
- README now highlights post-install security tasks and helper alias usage.

### Fixed
- Gluetun helper aliases authenticate using the required `X-Api-Key` header.
- Port-sync automation no longer relies on hard-coded qBittorrent credentials.
- `.arraliases` placeholders are replaced automatically during setup.
- LAN IP detection surfaces warnings instead of silently binding to all interfaces.

## [0.1.0] - 2024-01-15
- Initial prototype release.
