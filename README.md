# appleoauth

[![Go Reference](https://pkg.go.dev/badge/github.com/go-darwin/appleoauth.svg)](https://pkg.go.dev/github.com/go-darwin/appleoauth)

Package appleoauth provides the user/password login to Apple web service.

## Reference

### API Endpoints

- https://idmsa.apple.com:
  - Used to authenticate to get a valid session
- https://developerservices2.apple.com:
  - Get a list of all available provisioning profiles
  - Register new devices
- https://developer.apple.com:
  - List all devices, certificates, apps and app groups
  - Create new certificates, provisioning profiles and apps
  - Disable/enable services on apps and assign them to app groups
  - Delete certificates and apps
  - Repair provisioning profiles
  - Download provisioning profiles
  - Team selection
- https://appstoreconnect.apple.com:
  - Managing apps
  - Managing beta testers
  - Submitting updates to review
  - Managing app metadata
- https://du-itc.appstoreconnect.apple.com:
  - Upload icons, screenshots, trailers ...
- https://is[1-9]-ssl.mzstatic.com:
  - Download app screenshots from App Store Connect
