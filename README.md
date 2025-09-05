# Policyd client plugin

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-policyd-client
```

### RHEL

```
yum install halon-extras-policyd-client
```

## Configuration

The smtpd.yaml file provides configuration for this plugin.

### smtpd-app.yaml

```
config:
  address: path-of-websocket
```