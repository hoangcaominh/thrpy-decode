# thrpy-decode
Decoding utilities for Touhou Project replay files

## Setup
Clone this repository. After cloning, run `npm i` to install necessary packages for this project. Finally, run `node-gyp configure` to configure the project. Remember to run the command any time you make changes to `binding.gyp`.

## Build
To build the project, run `npm run build` or `npm run build:dev`, and the node module which has the `.node` extension should be in the `build/Debug` or `build/Release` folder, depending on which command you run.