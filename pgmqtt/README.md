<div align="center">

  <img src="docs/pgmqtt.png" alt="logo"/>
  <h1>Power-Generator MQTT Simulator</h1>
  
  <p>
    Power-Generator Simulator over MQTT
  </p>
  
<!-- Badges -->
<p>
  <a href="https://github.com/amine-amaach/simulators/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/amine-amaach/simulators" alt="contributors" />
  </a>
  <a href="https://github.com/amine-amaach/simulators/network/members">
    <img src="https://img.shields.io/github/forks/amine-amaach/simulators" alt="forks" />
  </a>
  <a href="https://github.com/amine-amaach/simulators/stargazers">
    <img src="https://img.shields.io/github/stars/amine-amaach/simulators" alt="stars" />
  </a>
  <a href="https://github.com/amine-amaach/simulators/issues/">
    <img src="https://img.shields.io/github/issues/amine-amaach/simulators" alt="open issues" />
  </a>
</p>
   
<h4>
    <a href="https://youtu.be/1XXsL2vwCGg">View Demo</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators/">Documentation</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators/issues/">Report Bug</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators/issues/">Request Feature</a>
  </h4>
</div>

<br />

<!-- Table of Contents -->
# 📒 Table of Contents

- [About the Project](#✨-about-the-project)
  * [Screenshots](#📷-screenshots)
- [Run the simulator](#🏃-run-the-simulator)
  * [Demo]()
- [Environment Variables](#⚙️-environment-variables)
- [Contact](#🤝-contact)
- [Contributing](#👋-contributing)
- [Acknowledgements](#💎-acknowledgements)

  

<!-- About the Project -->
## ✨ About the Project

* Power generators are basically small power-plants. They allow their owners to generate electricity on-site, as a substitute or complement to electricity from the electric grid.
* Power-Generator MQTT Simulator is a simulator producing fake IoT data over MQTT for use with the development of Industry 4.0 software solutions.
* Each generator will write to its own MQTT topic the following tags:
  - Load
  - Power
  - Temperature
  - Fuel Level
  - Base Fuel
  - Used Fuel

* Message payload for a generator :
```json
{"Name": "Generator_1", "Lat": -65.37906, "Lon": -62.64473, "Base Fuel": 909.3602}
```
* Message payload for a generator tag :
```json
{
  "ItemTopic": "Site/Area/Power-Generators/Generator_8/Load",
  "ItemId": "147377909",
  "ItemName": "Load",
  "ItemValue": 69,
  "ItemOldValue": 71,
  "ItemDataType": "INT",
  "ChangedTimestamp": "2022-07-10T06:42:59+01:00",
  "PreviousTimestamp": "2022-07-10T06:42:54+01:00"
}
```


<!-- Screenshots -->
### 📷 Screenshots

> Power-Generator MQTT microservice :
<div align="center"> 
  <img src="docs/screenshots/container.png" alt="screenshot" />
</div>

> MQTT Client subscribing to topics published by the microservice
<div align="center"> 
  <img src="docs/screenshots/mqttexplorer.png" alt="screenshot" />
</div>

<!-- Run Locally -->
### 🏃 Run the simulator

* The recommended way to run the simulator is by using docker : 

1. Clone this repository :
> This `microservice` is written in GO Programming Language and this repository contains the code source of the `microservice`.

> You can use the simulator as a docker container, it is available in DockerHub :
`docker pull amineamaach/simulators-pgmqtt`.
_you have to set the environment variables as in `docker-compose.yml` to configure MQTT connections and the simulator options_.

```bash
  git clone git@github.com:amine-amaach/simulators.git
```

2. Run

```bash
  docker-compose up
```
> `docker-compose` will pull the images and run the containers automatically as configured in `docker-compose.yml`.

> `docker-compose.yml` contains two images one for the simulator and the other for an EMQX MQTT Broker pre-configured with the simulator. If you want to use your own MQTT Broker change the env variables in the file.

> For this `microservice` you can set the configuration through the config file located in `sample-config/pgmqtt/config.json` or by using the environment variables in `docker-compose.yml`.

> _Note : Environment variables in `docker-compose.yml` will override the corresponding values in `config.json` if they exist._

3. Use an MQTT Client to subscribe to the generators topics.
> Default topic for all the generators : `Site/Area/Power-Generators/#`

### Demo :
* Check out a real example of using this simulator :
[Watch it on YouTube](https://youtu.be/nm6ARNTKCII)
<div align="center"> 
  <img src="docs/screenshots/pgmqtt-example.png" alt="pgmqtt-example" />
</div>

<!-- Roadmap -->
## 🛣️ Roadmap

- [x] Randomize the delay between messages separately for each generator.
- [x] Simulate multiple generators in a single `microservice`. 
- [ ] Support TLS connections.

## ⚙️ Environment Variables
The application is configured using the following environmental variables:

> SITE

* The ISA-95 Model site name. SITE used as the parent topic in the MQTT structure. If this is unset, _Site_ will be used.

> AREA

* The ISA-95 Model area name. AREA used as the second topic in the MQTT structure. If this is unset, _Area_ will be used.

> MQTT_SERVER_URL

* The address of the MQTT server.

> MQTT_SERVER_USER

* The name of the MQTT user with subscribe and publish permissions.

> MQTT_SERVER_PWD

* The password for the MQTT user with subscribe and publish permissions.

> MQTT_CLIENT_ID

* The client id to use when connecting to the broker.

> DELAY_BETWEEN_MESSAGES_MIN

* The minimum delay between messages in seconds. 

> DELAY_BETWEEN_MESSAGES_MAX

* The maximum delay between messages in seconds. 

> RANDOM_DELAY_BETWEEN_MESSAGES

* If set to `true` the delay between messages will be randomly generated based on `DELAY_BETWEEN_MESSAGES_MIN` and `DELAY_BETWEEN_MESSAGES_MIN` env variables, else `DELAY_BETWEEN_MESSAGES_MIN` will be set as fixed delay.

> GENERATORS_NUMBER

* The number of generators to simulate.

> GENERATORS_NUMBER_LIMIT

* The maximum number of generators to simulate, if `GENERATORS_NUMBER` > `GENERATORS_NUMBER_LIMIT` the number of generators will be set to `GENERATORS_NUMBER_LIMIT`



<!-- Contact -->
## 🤝 Contact

Amine Amaach - [LinkedIn](https://www.linkedin.com/in/amine-amaach/) - [Email](amine.amaach@um6p.ma)

Project Link: [https://github.com/amine-amaach/simulators.git](https://github.com/amine-amaach/simulators.git)

<!-- Contributing -->
## 👋 Contributing

<a href="https://github.com/amine-amaach/simulators/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=amine-amaach/simulators" />
</a>


Contributions are always welcome!
For major changes, please open an issue first to discuss what you would like to change.

<!-- Acknowledgments -->
## 💎 Acknowledgements & Inspiration

<!-- Use this section to mention useful resources and libraries that you have used in your projects. -->

 - [InfluxDB-Roadshow-Training](https://github.com/InfluxCommunity/InfluxDB-Roadshow-Training) 
 - [Zap](https://github.com/uber-go/zap)
 - [Viper](https://github.com/spf13/viper)
 - [Libre Technologies](https://github.com/Spruik/libre-common)
