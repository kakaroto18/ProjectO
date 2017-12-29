# Deploy ocserv on ubuntu 16.04+

## Requirements

1. Local computer with *nix installation
2. VPS running ubuntu 16.04+ that has been configured with SSH no-password login

## How to use

1. Install Ruby and gems (Ruby 2.3+ recommended)

```
# For example, on Ubuntu 16.04, you can run:
sudo apt-get install ruby gnutls-bin
sudo gem install sshkit sinatra
```

2. Checkout this project and prepare `config.yml`

```
cd PATH_TO_PROJECTO # Replace with real path
cp config.yml.skel config.yml
```

3. Edit `config.yml`. Change `domain`, `user_cert_password`, etc.

4. Start deploy:

```
ruby deploy.rb
```

## Client app

Version 4.5 of Cisco AnyConnect app (Windows, Linux, macOS) is included in `clients` directory. 

## About certificate

**Do not delete certificates in certs directory.**

If you want to deploy a new server, change `domain` in `config.yml` file and run deploy again.

`user.p12` is your user certificate that can be used in Cisco AnyConnect client or `openconnect` command line tool. The user certificate can be used for all your servers.

After deployment, a local webserver will run. You may use it for user certificate import. e.g. Cisco AnyConnect may need an web address to import user's p12 certificate.

```
http://YOUR_LOCAL_IP:4567/user.p12
# e.g. http://192.168.0.100:4567/user.p12
```

You may also find the p12 file under:

```
/PATH_TO_PROJECTO/certs/user.p12
```

If you don't need it, feel free to press Ctrl-C and stop script running.


