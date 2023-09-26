# thrpy-decode
Decoding utilities for Touhou Project replay files

## Setup
You will need to install `node-gyp` to compile the module. Run `npm i -g node-gyp` to install globally.

Clone this repository. After cloning, run `npm i` to install necessary packages for this project. `node-gyp` will automatically configure and build the project upon installing this package. During development, remember to run the command any time you make changes to `binding.gyp`.

## Build
To build the project, run `npm run build` or `npm run build:dev`, or `npm run rebuild` or `npm run rebuild:dev` to rebuild. The compiled Node module which has the `.node` extension should be in the `build/Debug` or `build/Release` folder, depending on which command you run.