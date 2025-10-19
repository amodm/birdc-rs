# Changelog

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2025-10-18 <a name="0.4.1"></a>
### Fixed
- Fix bug in handling whitespace in show protocol output

## [0.4.0] - 2025-08-08 <a name="0.4.0"></a>
### Added
- A `SyncConnection` for non-async environments. See PR #3

## [0.3.0] - 2022-05-02 <a name="0.3.0"></a>
### Added
- Make bird errors implement `std::error::Error` and `std::fmt::Display`. See PR #1

## [0.2.0] - 2022-05-02 <a name="0.2.0"></a>
### Added
- Semantic parsing of `show protocols` and `show protocols all`
- Semantic parsing of `show interfaces summary`

## [0.1.0] - 2022-04-30 <a name="0.1.0"></a>
### Added
- Initial release.

[Unreleased]: https://github.com/amodm/birdc-rs/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/amodm/birdc-rs/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/amodm/birdc-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/amodm/birdc-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/amodm/birdc-rs/compare/v0.1.0...v0.2.0
