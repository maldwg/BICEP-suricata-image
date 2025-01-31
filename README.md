<div align="center">
<img alt="Docker Image Version (tag)" src="https://img.shields.io/docker/v/maxldwg/bicep-suricata/latest?style=for-the-badge&logo=docker&label=Latest%20Version&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-suricata">
<img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/maxldwg/bicep-suricata?style=for-the-badge&logo=docker&logoColor=blue&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-suricata">

<br>

</div>

# BICEP-suricata-image
Suricata docker image adapated for BICEP

The image holds every dependency necessary along with the necessary interface implemented, in order to work with the BICEP application

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main)

## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```
git submodule update --init --recursive
```
This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.



## Building the project
TO build a local version of the image for testing purposes, simply run:
``` 
cd ./bicep-suricata
docker buildx build . --build-arg BASE_IMAGE=maxldwg/suricata --build-arg VERSION=7.0.6 -t maxldwg/bicep-suricata:latest --no-cache
```
Change the version to your desried one
