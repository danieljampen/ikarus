# To update the AV run the following:

```bash
$ docker run --name=ikarus malice/ikarus update
```

## Then to use the updated AVG container:

```bash
$ docker commit ikarus malice/ikarus:updated
$ docker rm ikarus # clean up updated container
$ docker run --rm malice/ikarus:updated EICAR
```
