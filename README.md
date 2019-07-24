# malice-ikarus

[![Circle CI](https://circleci.com/gh/malice-plugins/ikarus.png?style=shield)](https://circleci.com/gh/malice-plugins/ikarus) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/ikarus.svg)](https://store.docker.com/community/images/malice/ikarus) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/ikarus.svg)](https://store.docker.com/community/images/malice/ikarus) [![Docker Image](https://img.shields.io/badge/docker%20image-510MB-blue.svg)](https://store.docker.com/community/images/malice/ikarus)

Malice ikarus AntiVirus

> This repository contains a **Dockerfile** of [ikarus](https://www.ikarussecurity.com/solutions/all-solutions/sdksindustrial-security/ikarus-cmdscan) for [Docker](https://www.docker.com/)'s [trusted build](https://store.docker.com/community/images/malice/ikarus) published to the public [DockerHub](https://index.docker.io/).

---

### Dependencies

- [ubuntu:bionic (_84.1 MB_\)](https://hub.docker.com/_/ubuntu/)

## Installation


> **NOTE:** :warning: Requires license key and non public ikarus binaries. Request free trial at: - https://www.ikarussecurity.com/solutions/trials/demo-license-for-ikarus-antivirus/


1. Install [Docker](https://www.docker.com/).
2. Download [trusted build](https://store.docker.com/community/images/malice/ikarus) from public [docker store](https://store.docker.com): `docker pull malice/ikarus`
3. Request demo (https://www.ikarussecurity.com/solutions/trials/demo-license-for-ikarus-antivirus/) and download the provided files to a folder on your server. The following files will be provided by ikarus: libT3_l64.so, t3cmd.ikkey, t3scan_l64, t3update_l64.
4. Make sure the downloaded binaries are executable: chmod +x /ikarus/*

## Usage

```
docker run --rm -d --shm-size=256m -v IKARUS-BIN-FOLDER:/opt/ikarus malice/ikarus EICAR
```
**NOTE** As the ikarus binaries are not public, they are not included in the docker image and must be mounted into the container using `-v IKARUS-BIN-FOLDER:/opt/ikarus`.


### Or link your own malware folder:

```bash
$ docker run --rm --shm-size=256m -v IKARUS-BIN-FOLDER:/opt/ikarus -v /path/to/malware:/malware:ro malice/ikarus FILE

Usage: Ikarus [OPTIONS] COMMAND [arg...]

Malice Ikarus AntiVirus Plugin

Version: v0.1.0, BuildTime: 20190724

Author:
  betellen - <https://github.com/betellen>
  danieljampen - <https://github.com/danieljampen>
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V          verbose output
  --elasticsearch value  elasticsearch url for Malice to store results [$MALICE_ELASTICSEARCH_URL]
  --table, -t            output as Markdown table
  --callback, -c         POST results back to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x            proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --timeout value        malice plugin timeout (in seconds) (default: 120) [$MALICE_TIMEOUT]
  --help, -h             show help
  --version, -v          print the version

Commands:
  update  Update virus definitions
  web     Create a ikarus scan web service
  help    Shows a list of commands or help for one command

Run 'ikarus COMMAND --help' for more information on a command.
```

## Sample Output

### [JSON](https://github.com/malice-plugins/ikarus/blob/master/docs/results.json)

```json
{
  "ikarus": {
    "infected": true,
    "result": "EICAR Test-NOT virus!!!",
    "engine": "2.1.2",
    "database": "17012800",
    "updated": "20190724"
  }
}
```

### [Markdown](https://github.com/malice-plugins/ikarus/blob/master/docs/SAMPLE.md)

---

#### ikarus

| Infected | Result                  | Engine | Updated  |
| -------- | ----------------------- | ------ | -------- |
| true     | EICAR Test-NOT virus!!! | 2.1.2  | 20190724 |

---
## Documentation

- [To write results to ElasticSearch](https://github.com/malice-plugins/ikarus/blob/master/docs/elasticsearch.md)
- [To create a ikarus scan micro-service](https://github.com/malice-plugins/ikarus/blob/master/docs/web.md)
- [To post results to a webhook](https://github.com/malice-plugins/ikarus/blob/master/docs/callback.md)
- [To update the AV definitions](https://github.com/malice-plugins/ikarus/blob/master/docs/update.md)

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/ikarus/issues/new).

## TODO

## CHANGELOG

See [`CHANGELOG.md`](https://github.com/malice-plugins/ikarus/blob/master/CHANGELOG.md)

## Contributing

[See all contributors on GitHub](https://github.com/malice-plugins/ikarus/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/ikarus/blob/master/CHANGELOG.md) and submit a [Pull Request on GitHub](https://help.github.com/articles/using-pull-requests/).

## License

MIT Copyright (c) 2016 **blacktop**, **betellen**, **danieljampen**
