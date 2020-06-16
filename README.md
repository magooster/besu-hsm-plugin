# HSM Security Module Plugin

## Purpose of the Plugin
Persist a Besu node key in a HSM using the SunPKCS11Provider. Tested with SoftHSMv2. 

### Services Used
- **PicoCLIOptions** 
- **SecurityModuleSystem** 

### Plugin Lifecycle
- **Register** 
  * Register the plugin
- **Start** 
  * Not Used
- **Stop** 
  * Not Used

## To Build the Plugin

Build the plugin jar
```
./gradlew build
```

# Installation

Install the plugin into `$BESU_HOME`

```
mkdir $BESU_HOME/plugins
cp build/libs/*.jar $BESU_HOME/plugins
```

Run the Besu node
```
$BESU_HOME/bin/besu --config-file=options.toml --
```

# Testing with SoftHSM

## Initialize a slot

```
softhsm2-util --init-token --slot 0 --label besu
```  

## Create a besu compatible key using Java keytool (Need Java 12 for groupname support)

```
keytool -genkeypair -alias besu -keyalg EC -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg /path/to/pkcs11.cfg -groupname secp256k1 -dname CN=besu
```
## Enable the plugin

security-module="hsm"

## HSM Security Module Plugin Options

### Alias of the key in the keystore
plugin-hsm-key-alias="besu"

### Password (pin) for the keystore
plugin-hsm-keystore-password="12345"    

### PKCS11 provider configuration file path
plugin-hsm-keystore-config="./softhsm.cfg"

The above can be passed vi the cli using --plugin...

# Disclaimer

This is very much a demo for others to learn from - use at your own risk...