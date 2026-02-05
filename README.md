# ct-harvester

`ct-harvester` is a Certificate Transparency (CT) log sampling tool written in Go. Randomly samples entries from a set of specified CT logs and exports leaf certificates. Designed for large CT logs where sequential extraction was not desired.

##Features

- Random parallel sampling of CT log entires (X.509 certificates)
- PEM or text output
- Progress bars
- Based on Google CT libraries

