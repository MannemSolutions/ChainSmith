= Installation and usage of chainsmith

== with pip
It is as easy as 
- running pip install chainsmith
- creating or downloading a chainsmith.yaml (change at will)
- invoking chainsmith

A simple example on a fresh ubuntu would be like:
```
apt-get update && apt-get install -y python3-pip curl
curl https://raw.githubusercontent.com/MannemSolutions/ChainSmith/main/config/chainsmith.yml -o ./chainsmith.yml
pip install --upgrade pip && pip install chainsmith
chainsmith -c ./chainsmith.yml
```
It would look very similar on any other distribution.

== with docker
We have an image on dockerhub.
Using it could be as simpel as:
- creating or downloading a chainsmith.yaml (change at will)
- running the container

A simple example could be:
```
curl https://raw.githubusercontent.com/MannemSolutions/ChainSmith/main/config/chainsmith.yml -o ./chainsmith.yml
docker run -ti -v $PWD:/etc/chainsmith mannemsolutions/chainsmith
```
