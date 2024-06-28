# local test script to build RITA as an amd64 Docker image and export it to a file
VERSION=$(git describe --always --abbrev=0 --tags)

sudo docker buildx build  --platform linux/amd64 --tag ghcr.io/activecm/rita:"$VERSION" ../
docker save -o rita-"$VERSION"-image.tar ghcr.io/activecm/rita:"$VERSION"