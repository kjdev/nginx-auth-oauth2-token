# Installation

Installation instructions for the nginx auth_oauth2_token module.

## Prerequisites

### Required Libraries

- **nginx**: 1.18.0 or later
- **jansson**: 2.14 or later (for JSON processing; uses APIs such as `json_string_length()`)

### Package Installation Examples

**Debian/Ubuntu**:
```bash
apt-get install -y \
    build-essential \
    zlib1g-dev \
    libjansson-dev
```

**RHEL/CentOS/Fedora**:
```bash
dnf install -y \
    gcc \
    make \
    zlib-devel \
    jansson-devel
```

**Alpine Linux**:
```bash
apk add \
    gcc \
    make \
    musl-dev \
    zlib-dev \
    jansson-dev
```

## Building from Source

### Step 1: Obtain nginx Source Code

```bash
# Download nginx source code (adjust version as needed)
wget https://nginx.org/download/nginx-x.y.z.tar.gz
tar -xzf nginx-x.y.z.tar.gz
cd nginx-x.y.z
```

### Step 2: Run configure

```bash
./configure \
    --with-compat \
    --add-dynamic-module=..
```

**Options**:
- `--with-compat`: Enables dynamic module compatibility
- `--add-dynamic-module`: Builds the auth_oauth2_token module as a dynamic module

### Step 3: Build

```bash
make modules
```

### Step 4: Verify the Module

On successful build, the dynamic module is generated:

```bash
ls -l objs/ngx_http_auth_oauth2_token_module.so
```

### Step 5: Load the Module

Add the following to the top level of the nginx configuration file (typically `/etc/nginx/nginx.conf`):

```nginx
load_module "/path/to/objs/ngx_http_auth_oauth2_token_module.so";
```

### Step 6: Verify Configuration and Start

```bash
# Verify configuration
nginx -t

# Start nginx (or reload)
nginx -s reload
```

**Note**:
- This guide covers basic build steps only
- For system installation (`make install`), follow procedures appropriate for your environment

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directives and variables reference
- [SECURITY.md](SECURITY.md): Security considerations (cache settings included)
