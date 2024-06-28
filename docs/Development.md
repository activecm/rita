
## Development
There are two options for a development setup.

The `.env` file is setup for the development build. The `.env.production` file is copied over to the RITA container during the image build process. When running RITA in Docker, the regular `.env` file is still loaded by Docker since the paths for the files to mount to are relative to the repository. A production install copies the `.env.production` file to `/opt/rita`.

Note: Your usage of `sudo` in relation to these instructions may change depending on your system.

#### Rapid Development
For rapid development, RITA is not ran in Docker. The plain `docker-compose.yml` file exposes the database on the host! If you are running this in an environment where this is not ideal, please follow the instructions for Docker Development.

Start the backend containers for Clickhouse:
```
docker compose up -d
```

Run RITA:
    * Using Go:
        ```
        go run main.go <command> <flags>
        ```
    * Using a Compiled Binary and Versioning:
        ```
        make
        ./rita <command> <flags>
        ```


#### Docker Development
The installed version of RITA uses the `rita.sh` script to run RITA in Docker. For more fine-grained control of the build process, see the following:

Build the RITA image:
```
sudo docker compose -f docker-compose.yml build
```
If this refuses to build, you may need to tell Docker what platform you're on:
```
export DOCKER_DEFAULT_PLATFORM=linux/arm64 && sudo docker compose -f docker-compose.prod.yml build
```
Reload the containers
```
docker compose -f docker-compose.prod.yml up -d
```
Run RITA:
```
docker compose -f docker-compose.prod.yml run --rm -it rita .....
```