<div align="center">

  <img src="docs/simulators.png" alt="logo"/>
  <h1>MQTT simulators</h1>
  
  <p>
    An MQTT simulators Simulator
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
    <a href="https://github.com/amine-amaach/simulators/">View Demo</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators">Documentation</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators/issues/">Report Bug</a>
  <span> · </span>
    <a href="https://github.com/amine-amaach/simulators/issues/">Request Feature</a>
  </h4>
</div>

<br />

<!-- Table of Contents -->
# 📒 Table of Contents

- [About the Project](#star2-about-the-project)
  * [Screenshots](#camera-screenshots)
  <!-- * [Environment Variables](#key-environment-variables) -->
- [Run Locally](#running-run-locally)
- [Usage](#eyes-usage)
- [Roadmap](#compass-roadmap)
- [Contributing](#wave-contributing)
- [Contact](#handshake-contact)
- [Acknowledgements](#gem-acknowledgements)

  

<!-- About the Project -->
## ✨ About the Project


<!-- Screenshots -->
### 📷 Screenshots

* Power generators are basically small power-plants. They allow their owners to generate electricity on-site, as a substitute or complement to electricity from the electric grid.
* This simulator simulates these power generators data and publish it to an MQTT broker.

<div align="center"> 
  <img src="docs/screenshots/screenshot-v1.0.0.png" alt="screenshot" />
</div>

<!-- Features -->
### 🎯 Features

- Power generators data simulation.
- Simulate multiple power generators.
- Publish data to MQTT brokers.
- ...


<!-- Env Variables
### :key: Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`API_KEY`

`ANOTHER_API_KEY` -->


<!-- Installation
### :gear: Installation

Install my-project with npm

```bash
``` -->
   
<!-- Running Tests
### :test_tube: Running Tests

To run tests, run the following command

```bash
  make test
``` -->

<!-- Run Locally -->
### 🏃 Run Locally

Clone the project

```bash
  git clone git@github.com:amine-amaach/simulators.git
```

Go to the project directory

```bash
  cd simulators/pgmqtt
```

<!-- Install dependencies

```bash
  go mod tidy
``` -->

Start the simulator

```bash
  go run cmd/pgmqtt/main.go
```



<!-- Usage
## :eyes: Usage

Use this space to tell a little more about your project and how it can be used. Show additional screenshots, code samples, demos or link to other resources.


```go
import Component from 'my-project'

function App() {
  return <Component />
}
``` -->


<!-- Roadmap -->
## 🛣️ Roadmap

- [x] Randomize the delay between messages separately for each generator.
- [x] Simulate multiple generators in a single microservice. 
- [x] Concurrent Simulator.
- [ ] Set up TLS connection.


<!-- Contributing -->
## 👋 Contributing

<a href="https://github.com/amine-amaach/simulators/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=amine-amaach/simulators" />
</a>


Contributions are always welcome!

<!-- See `contributing.md` for ways to get started. -->

<!-- License -->
## ⚠️ License

Distributed under the no License. See LICENSE.txt for more information.

<!-- Contact -->
## 🤝 Contact

Amine Amaach - [LinkedIn](https://www.linkedin.com/in/amine-amaach/) - [Email](amine.amaach@um6p.ma)

Project Link: [https://github.com/amine-amaach/simulators.git](https://github.com/amine-amaach/simulators.git)


<!-- Acknowledgments -->
## 💎 Acknowledgements

<!-- Use this section to mention useful resources and libraries that you have used in your projects. -->

 - [InfluxDB-Roadshow-Training](https://github.com/InfluxCommunity/InfluxDB-Roadshow-Training) 
 - [Zap](https://github.com/uber-go/zap)
 - [Viper](https://github.com/spf13/viper)
 - [Libre Technologies](https://github.com/Spruik/libre-common)
